#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Data::Dumper;
use IO::File;
use Linux::Landlock::Direct qw(:all);

my $abi_version = ll_get_abi_version();
if ($abi_version < 0) {
    BAIL_OUT("Landlock not available");
}
ok($abi_version > 0,                          "Landlock available, ABI version $abi_version");
ok(scalar ll_all_fs_access_supported() >= 13, "plausible list");
my $ruleset_fd = ll_create_ruleset();
ok($ruleset_fd > 0, "ruleset created");
opendir(my $dh, "data") or die $!;
my $writable_fh = IO::File->new('data/b', 'r');
ll_add_rule(
    $ruleset_fd,
    $LANDLOCK_RULE{PATH_BENEATH},
    $LANDLOCK_ACCESS_FS{READ_FILE} | $LANDLOCK_ACCESS_FS{WRITE_FILE} | $LANDLOCK_ACCESS_FS{TRUNCATE}, $writable_fh
);
ll_add_rule($ruleset_fd, $LANDLOCK_RULE{PATH_BENEATH}, $LANDLOCK_ACCESS_FS{READ_FILE}, $dh);
$writable_fh->close();
ok(!defined ll_add_rule(fileno(*STDIN), $LANDLOCK_RULE{PATH_BENEATH}, $LANDLOCK_ACCESS_FS{READ_FILE}, $dh),
    "attempt to add rule to wrong fd: $!");
ok(!defined ll_restrict_self($ruleset_fd), "no_new_privs not set: $!");
set_no_new_privs();
ok(ll_restrict_self($ruleset_fd), "successfully restricted");
ok(IO::File->new('data/a',  'r'), 'can read from file in data');
ok(!IO::File->new('data/a', 'w'), 'cannot write to file in data');
ok(!IO::File->new($0,       'r'), 'cannot read file outside of data');
ok(IO::File->new('data/b',  'r'), 'can read from other file in data');
ok(IO::File->new('data/b',  'w'), 'can write to other file in data');
done_testing();
