package Linux::Landlock::Direct;

=head1 NAME

Linux::Landlock::Direct - Direct, low-level interface to the Linux Landlock API

=head1 DESCRIPTION

This module provides a functional interface to the Linux Landlock API.
It is a thin wrapper around the Landlock system calls.

See L<Linux::Landlock::Ruleset> for a higher-level OO and exception based interface.

=head1 SYNOPSIS

    use Linux::Landlock::Direct qw(:all);

    # create a new ruleset with all supported actions
    my $ruleset_fd = ll_create_ruleset();
    opendir my $dir, '/tmp';
    # allow read and write access to files in /tmp, truncate is typically also needed, depending on the open call
    ll_add_rule($ruleset_fd,
        $LANDLOCK_RULE{PATH_BENEATH},
        $LANDLOCK_ACCESS_FS{READ_FILE} | $LANDLOCK_ACCESS_FS{WRITE} | $LANDLOCK_ACCESS_FS{TRUNCATE},
        $dir,
    );
    # NO_NEW_PRIVS is required for ll_restrict_self() to work, it can be set by any means, e.g. inherited or
    # set via some other module; this implementation just exists for convenience
    set_no_new_privs();
    # apply the ruleset to the current process and its children. This cannot be undone.
    ll_restrict_self($ruleset_fd);

=head1 FUNCTIONS

=over 1

=item ll_get_abi_version()

Int, returns the ABI version of the Landlock implementation. Minimum version is 1.
Returns -1 on error.

=item ll_create_ruleset(@actions)

Int (file descriptor), creates a new Landlock ruleset that covers the specified actions.
If no actions are specified, all supported actions are covered.

Returns the file descriptor of the new ruleset on success, or undef on error.

=item ll_add_rule($rule_fd, $rule_type, $allowed_access, $parent_fh)

=back

=cut

use strict;
use warnings;
use Exporter 'import';
use List::Util qw(reduce);
require 'sys/syscall.ph';

# adapted from linux/landlock.ph, architecture independent
# ABI version 1
my $LANDLOCK_CREATE_RULESET_VERSION = (1 << 0);
our %LANDLOCK_ACCESS_FS = (
    # ABI version 1
    EXECUTE     => (1 << 0),
    WRITE_FILE  => (1 << 1),
    READ_FILE   => (1 << 2),
    READ_DIR    => (1 << 3),
    REMOVE_DIR  => (1 << 4),
    REMOVE_FILE => (1 << 5),
    MAKE_CHAR   => (1 << 6),
    MAKE_DIR    => (1 << 7),
    MAKE_REG    => (1 << 8),
    MAKE_SOCK   => (1 << 9),
    MAKE_FIFO   => (1 << 10),
    MAKE_BLOCK  => (1 << 11),
    MAKE_SYM    => (1 << 12),
    # ABI version 2
    REFER => (1 << 13),
    # ABI version 3
    TRUNCATE => (1 << 14),
);
our %LANDLOCK_ACCESS_NET = (
    # ABI version 4
    BIND_TCP    => (1 << 0),
    CONNECT_TCP => (1 << 1),
);
our %LANDLOCK_RULE = (
    PATH_BENEATH => 1,
    NET_PORT     => 2,
);
our @EXPORT_OK = qw(
  ll_get_abi_version
  ll_create_ruleset
  ll_add_rule
  ll_all_fs_access_supported
  ll_restrict_self
  set_no_new_privs
  %LANDLOCK_ACCESS_FS
  %LANDLOCK_ACCESS_NET
  %LANDLOCK_RULE
);
our %EXPORT_TAGS = (
    methods   => [grep { /^ll_/x } @EXPORT_OK],
    constants => [grep { /^%/x } @EXPORT_OK],
);
$EXPORT_TAGS{all} = ['set_no_new_privs', map { @$_ } @EXPORT_TAGS{qw(methods constants)}];

my %max_fs_supported = (
    -1 => 0,
    1  => $LANDLOCK_ACCESS_FS{MAKE_SYM},
    2  => $LANDLOCK_ACCESS_FS{REFER},
    3  => $LANDLOCK_ACCESS_FS{TRUNCATE},
);

sub ll_all_fs_access_supported {
    my $version = ll_get_abi_version();
    $version = 3 if $version > 3; # no new FS access types in version 4
    return grep { $_ <= $max_fs_supported{$version} } values %LANDLOCK_ACCESS_FS;
}

sub ll_get_abi_version {
    return syscall(&SYS_landlock_create_ruleset, undef, 0, $LANDLOCK_CREATE_RULESET_VERSION);
}

sub ll_create_ruleset {
    my (@actions) = @_;
    # handle all known and supported actions if none are specified
    @actions = ll_all_fs_access_supported() unless @actions;
    return unless @actions;
    my $packed_attr = pack('Q', reduce { $a | $b } @actions);
    my $fd = syscall(&SYS_landlock_create_ruleset, $packed_attr, length $packed_attr, 0);
    if ($fd >= 0) {
        return $fd;
    } else {
        return;
    }
}

sub ll_add_rule {
    my ($ruleset_fd, $rule_type, $allowed_access, $parent_fh) = @_;
    return (
        syscall(&SYS_landlock_add_rule, $ruleset_fd, $rule_type, pack('Ql', $allowed_access, fileno $parent_fh), 0) ==
          0) ? 1 : undef;
}

sub set_no_new_privs {
    my $PR_SET_NO_NEW_PRIVS = 38;
    return (syscall(&SYS_prctl, $PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0) ? 1 : undef;
}

sub ll_restrict_self {
    my ($ruleset_fd) = @_;
    return (syscall(&SYS_landlock_restrict_self, $ruleset_fd, 0) == 0) ? 1 : undef;
}

1;
