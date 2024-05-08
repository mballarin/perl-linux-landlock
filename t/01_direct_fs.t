#!/usr/bin/perl

use strict;
use warnings;
use Test::More;
use Data::Dumper;
use IO::File;
use Linux::Landlock::Direct qw(:functions :constants set_no_new_privs);

my $abi_version = ll_get_abi_version();
if ($abi_version < 0) {
    BAIL_OUT("Landlock not available");
}
ok($abi_version > 0,                          "Landlock available, ABI version $abi_version");
ok(scalar ll_all_fs_access_supported() >= 13, "plausible list");
my $ruleset_fd = ll_create_fs_ruleset();
ok($ruleset_fd > 0, "ruleset created");
opendir(my $dh, "data") or BAIL_OUT("$!");
my $writable_fh = IO::File->new('data/b', 'r');
ok(
    ll_add_path_beneath_rule(
        $ruleset_fd,
        $LANDLOCK_ACCESS_FS{READ_FILE} | $LANDLOCK_ACCESS_FS{WRITE_FILE}, $writable_fh
    ),
    'rule added'
);
ok(ll_add_path_beneath_rule($ruleset_fd, $LANDLOCK_ACCESS_FS{READ_FILE}, $dh), 'rule added');
$writable_fh->close();
ok(!defined ll_add_path_beneath_rule(fileno(*STDIN), $LANDLOCK_ACCESS_FS{READ_FILE}, $dh), "attempt to add rule to wrong fd: $!");
ok(!defined ll_restrict_self($ruleset_fd),                                       "no_new_privs not set: $!");
ok(set_no_new_privs(),                                                           "no_new_privs set");
ok(ll_restrict_self($ruleset_fd),                                                "successfully restricted");
ok(IO::File->new('data/a', '<'),                                                 'can read from file in data');
ok(!IO::File->new('data/a', '>>'),                                                'cannot write to file in data');
ok(!IO::File->new($0, '<'),                                                      'cannot read file outside of data');
ok(IO::File->new('data/b', '<'),                                                 'can read from other file in data');
ok(IO::File->new('data/b', '>>'),                                                 'can write to other file in data');
done_testing();
