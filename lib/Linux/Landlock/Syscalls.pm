package Linux::Landlock::Syscalls;

use strict;
use warnings;
use Config;
use Exporter 'import';
our @EXPORT_OK = qw(NR);

my %SYSCALLS;

sub NR {
    my ($name) = @_;

    if (!%SYSCALLS) {
        my $re_arm     = qr/arm/x;
        my $re_aarch64 = qr/aarch64/x;
        my $re_x86     = qr/i686/x;
        my $re_x86_64  = qr/x86_64/x;
        if (my ($arch) = $Config{archname} =~ /($re_x86_64|$re_x86|$re_arm|$re_aarch64)/x) {
            my %prctl = (
                aarch64 => 167,
                arm     => 172,
                i686    => 172,
                x86_64  => 157,
            );
            %SYSCALLS = (
                landlock_create_ruleset => 444,
                landlock_add_rule       => 445,
                landlock_restrict_self  => 446,
                prctl                   => $prctl{$arch},
            );
        } elsif (eval { require 'syscall.ph'; 1 } || eval { require 'sys/syscall.ph'; 1 }) {
            %SYSCALLS = (
                landlock_create_ruleset => &SYS_landlock_create_ruleset,
                landlock_add_rule       => &SYS_landlock_add_rule,
                landlock_restrict_self  => &SYS_landlock_restrict_self,
                prctl                   => &SYS_prctl,
            );
        } else {
            die <<"MSG";
Could not load header files and got no hardcoded syscall numbers for '$Config{archname}'.
Either generate headers via 'h2ph' or add the syscall numbers for your architecture to the module.
MSG
        }
    }
    return $SYSCALLS{$name};
}

1;