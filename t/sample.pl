      use Linux::Landlock::Ruleset;

      my $ruleset = Linux::Landlock::Ruleset->new();
      $ruleset->add_path_rule('/etc', qw(read_file read_dir));
      $ruleset->allow_perl_inc_access(); # allow loading Perl modules
      $ruleset->apply();
      print -r '/proc/cpuinfo' ? "allowed\n" : "not allowed\n"; # allowed
      IO::File->new('/etc/passwd', 'r') and print "succeeded\n"; # succeeded
      print -r '/proc/cpuinfo' ? "allowed\n" : "not allowed\n"; # allowed
      IO::File->new('/proc/cpuinfo', 'r') or print "failed: $!\n"; # ...but Landlock will prevent it => failed
      print -x '/usr/bin/cat' ? "allowed\n" : "not allowed\n"; # allowed
      print -r '/usr/bin/cat' ? "allowed\n" : "not allowed\n"; # allowed
      system('/usr/bin/cat /etc/passwd') and print "failed: $!\n"; # failed

