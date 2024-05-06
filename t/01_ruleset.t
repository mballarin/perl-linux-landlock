#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use Linux::Landlock::Ruleset;
use Data::Dumper;
use IO::File;
use IO::Dir;

my $ruleset = Linux::Landlock::Ruleset->new();
ok($ruleset->allow_perl_inc_access(), "allow_perl_inc_access");
ok($ruleset->add_path_rule('data', qw(read_file)), "allow read_file in data");
ok($ruleset->add_path_rule('/usr', qw(execute read_file)), "allow read_file + execute in /usr");
ok($ruleset->allow_std_dev_access(), "allow_std_dev_access");
ok($ruleset->apply(), "apply ruleset");
for (@INC) {
    ok(IO::Dir->new($_), "opendir $_");
}
for (qw(/ /var)) {
    ok(-r $_, "technically readable: $_");
    ok(!defined IO::Dir->new($_), "opendir $_ failed");
}
ok(defined IO::File->new('data/a', 'r'), "readable: data/a");
ok(defined IO::File->new('data/b', 'r'), "readable: data/b");
is(system('/usr/bin/cat data/a'), 0, "cat data/a is allowed...");
is(system('/usr/bin/cat data/a > /dev/null'), 0, "... as is writing to /dev/null");
my $ruleset2 = Linux::Landlock::Ruleset->new();
ok($ruleset2->allow_perl_inc_access(), "allow_perl_inc_access");
ok($ruleset2->add_path_rule('data/a', qw(read_file)), "allow read_file on data/a");
ok($ruleset2->apply(), "apply ruleset");
ok(-r 'data/b', "technically readable: data/b");
ok(!defined IO::File->new('data/b', 'r'), "no longer readable: data/b");
ok(defined IO::File->new('data/a', 'r'), "still readable: data/a...");
is(system('/usr/bin/cat data/a'), -1, "...but no permission to run cat");
for (@INC) {
    ok(IO::Dir->new($_), "opendir $_");
}
done_testing();

