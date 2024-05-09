use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    ABSTRACT           => 'An interface to the Landlock sandboxing facility of Linux',
    AUTHOR             => 'Marc Ballarin <ballarin.marc@gmx.de>',
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0
    },
    DISTNAME      => 'Linux-Landlock',
    LICENSE       => 'perl',
    NAME          => 'Linux::Landlock',
    PREREQ_PM     => {},
    VERSION       => '0.500',
    TEST_REQUIRES => {
        'Test::More' => '0.47'
    },
    test => {
        TESTS => 't/*.t'
    },
    META_MERGE => {
        'meta-spec' => { version => 2 },
        resources   => {
            repository => {
                type => 'git',
                url  => 'https://github.com/mballarin/perl-linux-landlock.git',
                web  => 'https://github.com/mballarin/perl-linux-landlock',
            },
            bugtracker => {
                web => 'https://github.com/mballarin/perl-linux-landlock/issues'
            },
        },
    },
);
