package Linux::Landlock::Ruleset;

=head1 NAME

Linux::Landlock::Ruleset - A higher level interface to the Linux Landlock API

=head1 SYNOPSIS

      use Linux::Landlock::Ruleset;

      my $ruleset = Linux::Landlock::Ruleset->new();
      $ruleset->add_path_rule('/etc/cpuinfo', qw(read_file read_dir));
      $ruleset->add_net_rule(22222, qw(bind_tcp));
      $ruleset->apply();

      print -r '/proc/cpuinfo' ? "allowed\n" : "not allowed\n"; # allowed ...
      IO::File->new('/proc/cpuinfo', 'r') and print "succeeded: $!\n"; # ... and opening works
      system('/usr/bin/cat /etc/cpuinfo') and print "failed: $!\n"; # but this fails, because we cannot execute cat
      print -r '/proc/passwd' ? "allowed\n" : "not allowed\n"; # allowed ...
      IO::File->new('/etc/passwd', 'r') or print "failed\n"; # ... but opening fails

      IO::Socket::INET->new(LocalPort => 33333, Proto => 'tcp') or print "failed: $!\n"; # failed
      IO::Socket::INET->new(LocalPort => 22222, Proto => 'tcp') and print "succeeded\n"; # succeeded

=head1 METHODS

=over 1

=item apply()

Apply the ruleset to the current process and all children. Dies on error.

=item get_abi_version()

Int, returns the ABI version of the Landlock kernel module. Can be called as a static method.
A version < 1 means that Landlock is not available.

=item add_path_rule($path, @allowed)

Add a rule to the ruleset that allows the specified access to the given path.
C<$path> can be a file or a directory. C<@allowed> is a list of access rights to allow.

Possible access rights are:

    execute
    write_file
    read_file
    read_dir
    remove_dir
    remove_file
    make_char
    make_dir
    make_reg
    make_sock
    make_fifo
    make_block
    make_sym
    refer
    truncate

=item add_net_rule($port, @allowed)

Add a rule to the ruleset that allows the specified access to the given port.
C<$port> is allowed port, C<@allowed> is a list of allowed operations.

Poossible operations are:

    bind_tcp
    connect_tcp

=item allow_perl_inc_access()

A convenience method that adds rules to allow reading files and directories in all directories in C<@INC>.

=item new([handled_actions => \@actions])

Create a new L<Linux::Landlock::Ruleset> instance. C<handled_actions> restricts the set of actions
that can be used in rules and that will be prevented if not allowed by any rule.

By default, all actions supported by the kernel and known to this module are covered. This should usually
not be changed.

=back

=cut

use strict;
use warnings;
use List::Util qw(reduce);
use IO::Dir;
use IO::File;
use Linux::Landlock::Direct qw(
  %LANDLOCK_RULE
  %LANDLOCK_ACCESS_FS
  %LANDLOCK_ACCESS_NET
  ll_add_fs_rule
  ll_add_net_rule
  ll_restrict_self
  ll_get_abi_version
  ll_create_fs_ruleset
  ll_create_net_ruleset
  set_no_new_privs
);

sub new {
    my ($class, %args) = @_;
    die "Landlock is not available\n" if ll_get_abi_version() < 1;
    my $self = bless {}, $class;
    $self->{handled_fs_actions}  = ref $args{handled_fs_actions} eq 'ARRAY'  ? $args{handled_fs_actions}  : [];
    $self->{handled_net_actions} = ref $args{handled_net_actions} eq 'ARRAY' ? $args{handled_net_actions} : [];
    return $self;
}

sub apply {
    my ($self) = @_;
    set_no_new_privs() or die "Failed to set no_new_privs: $!\n";
    if (defined $self->{_fs_fd}) {
        ll_restrict_self($self->{_fs_fd}) or die "Failed to restrict self: $!\n";
    }
    if (defined $self->{_net_fd}) {
        ll_restrict_self($self->{_net_fd}) or die "Failed to restrict self: $!\n";
    }
    return 1;
}

sub get_abi_version {
    return ll_get_abi_version();
}

sub add_path_rule {
    my ($self, $path, @allowed) = @_;
    $self->{_fs_fd} = ll_create_fs_ruleset(@{ $self->{handled_fs_actions} })
      or die "Failed to create ruleset: $!\n"
      unless defined $self->{_fs_fd};
    if (my $fh = -d $path ? IO::Dir->new($path) : IO::File->new($path)) {
        my $allowed = reduce { $a | $b } map { $LANDLOCK_ACCESS_FS{ uc $_ } } @allowed;
        ll_add_fs_rule($self->{_fs_fd}, $allowed, $fh) or die "Failed to add rule: $!\n";
        return 1;
    } else {
        die "Failed to open $path: $!\n";
    }
}

sub add_net_rule {
    my ($self, $port, @allowed) = @_;
    $self->{_net_fd} = ll_create_net_ruleset(@{ $self->{handled_net_actions} })
      or die "Failed to create ruleset: $!\n"
      unless defined $self->{_net_fd};
    my $allowed = reduce { $a | $b } map { $LANDLOCK_ACCESS_NET{ uc $_ } } @allowed;
    ll_add_net_rule($self->{_net_fd}, $allowed, $port) or die "Failed to add rule: $!\n";
    return 1;
}

sub allow_perl_inc_access {
    my ($self) = @_;

    for (@INC) {
        next unless -d $_;
        $self->add_path_rule($_, qw(read_file read_dir));
    }
    return 1;
}

sub allow_std_dev_access {
    my ($self) = @_;

    for (qw(null zero random urandom)) {
        $self->add_path_rule("/dev/$_", qw(read_file write_file));
    }
    return 1;
}

1;
