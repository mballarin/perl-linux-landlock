# NAME

Linux::Landlock::Ruleset - A higher level interface to the Linux Landlock API

# SYNOPSIS

      use Linux::Landlock::Ruleset;

      my $ruleset = Linux::Landlock::Ruleset->new();
      $ruleset->add_path_rule('/etc/fstab', qw(read_file));
      $ruleset->add_net_rule(22222, qw(bind_tcp));
      $ruleset->apply();

      print -r '/etc/fstab' ? "allowed\n" : "not allowed\n"; # allowed ...
      IO::File->new('/etc/fstab', 'r') and print "succeeded: $!\n"; # ... and opening works
      print -r '/etc/passwd' ? "allowed\n" : "not allowed\n"; # allowed ...
      IO::File->new('/etc/passwd', 'r') or print "failed\n"; # ... but opening fails because of Landlock

      system('/usr/bin/cat /etc/fstab') and print "failed: $!\n"; # this fails, because we cannot execute cat

      IO::Socket::INET->new(LocalPort => 33333, Proto => 'tcp') or print "failed: $!\n"; # failed
      IO::Socket::INET->new(LocalPort => 22222, Proto => 'tcp') and print "succeeded\n"; # succeeded

# METHODS

- apply()

    Apply the ruleset to the current process and all future children. Dies on error.

- get\_abi\_version()

    Int, returns the ABI version of the Landlock kernel module. Can be called as a static method.
    A version < 1 means that Landlock is not available.

- add\_path\_beneath\_rule($path, @allowed)

    Add a rule to the ruleset that allows the specified access to the given path.
    `$path` can be a file or a directory. `@allowed` is a list of access rights to allow.

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

- add\_net\_port\_rule($port, @allowed)

    Add a rule to the ruleset that allows the specified access to the given port.
    `$port` is allowed port, `@allowed` is a list of allowed operations.

    Possible operations are:

        bind_tcp
        connect_tcp

- allow\_perl\_inc\_access()

    A convenience method that adds rules to allow reading files and directories in
    all directories in `@INC`.

- new(\[handled\_actions => \\@actions\])

    Create a new [Linux::Landlock::Ruleset](https://metacpan.org/pod/Linux%3A%3ALandlock%3A%3ARuleset) instance.

    `handled_actions` restricts the set of actions that can be used in rules and that
    will be prevented if not allowed by any rule.
    By default, all actions supported by the kernel and known to this module are covered.
    This should usually not be changed.

# AUTHOR

Marc Ballarin, <ballarin.marc@gmx.de>

# COPYRIGHT AND LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.
