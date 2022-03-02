#!/usr/bin/perl
#
# Joao Victor A. di Stasi
# jvictor@cos.ufrj.br
# PESC/COPPE/UFRJ 2006

use strict;
use warnings;
use Getopt::Long qw(:config no_ignore_case bundling);
use Term::ReadKey;
use Time::Local;
use Net::LDAP;
use Net::LDAP::Entry;
use POSIX;

our %opt  = ();
our %ldap = ();

my @user_r = ();
my @ldapfile_r =
  ( '/etc/libnss-ldap.conf', '/etc/ldap.conf', '/etc/ldap/ldap.conf' );
my @ldapsecret_r = ( '/etc/libnss-ldap.secret', '/etc/ldap.scret' );
my @ldap_modify = ();

my $ldap = 0;
my $mesg = 0;

unless (
    GetOptions(
        "help|h" => sub { &usage('Ajuda'); exit 0 },
        "verbose|v" => sub { $opt{verbose} = 1 },
        "debug|x"   => sub { $opt{debug}   = 1 },
        "lastday|d=s"    => \$opt{shadowLastChange},
        "expiredate|E=s" => \$opt{shadowExpire},
        "host|H=s"       => \$ldap{host},
        "inactive|I=i"   => \$opt{shadowInactive},
        "list|l"         => sub { $opt{list} = 1 },
        "mindays|m=i"    => \$opt{shadowMin},
        "maxdays|M=i"    => \$opt{shadowMax},
        "warndays|W=i"   => \$opt{shadowWarning},
        "binddn|D=s"     => \$ldap{rootbinddn},
        "basedn|b=s"     => \$opt{basedn},
    )
  )
{
    &usage("");
    exit 1;
}

get_user_list();
proc_opts();

#exit 0;
ldap_bind();

foreach my $user (@user_r) {
    set_ldap_user_configs($user)  if (@ldap_modify);
    print_user_information($user) if ( $opt{list} );

}

ldap_unbind();

sub get_user_list {
    unless (@ARGV) {
        &usage("Usuário inválido!");
        exit 1;

    }
    print "Lista de usuários: " if ( $opt{verbose} );
    foreach (@ARGV) {
        if (m/[a-z]+/) {
            push( @user_r, $_ );
            print $_ . " " if ( $opt{verbose} );
        }
        elsif (m/-/) {
            my @b = ();
            while ( my $line = <STDIN> ) {
                chomp($line);
                my @c = split( / /, $line );
                push( @b, @c );
            }
            foreach (@b) {
                if (m/[a-z]+/) {
                    push( @user_r, $_ );
                    print $_ . " " if ( $opt{verbose} );
                }
                else {
                    &usage("$_ Usuário inválido!");
                    exit 1;
                }

            }

        }
        else {
            &usage("$_ Usuário inválido!");
            exit 1;
        }
    }
    print "\n" if ( $opt{verbose} );
}

#Processa apenas as opções que são strings
sub proc_opts {

    if ( $opt{shadowInactive} ) {
        proc_shadowInactive();
    }
    if ( $opt{shadowWarning} ) {
        proc_shadowWarning();
    }
    if ( $opt{shadowMax} ) {
        proc_shadowMax();
    }
    if ( $opt{shadowMin} ) {
        proc_shadowMin();
    }
    if ( $opt{shadowLastChange} ) {
        proc_shadowLastChange();
    }
    if ( $opt{shadowExpire} ) {
        proc_shadowExpire();
    }

    if ( $ldap{rootbinddn} ) {
        proc_rootbinddn();
    }
    else {
        find_ldap_auto_config();
    }
    if ( $opt{list} ) {
        if (@ldap_modify) {
            &usage("Combinação de opções inválida: -l e modificações");
            exit(1);
        }
    }

    print "Modificaçoes: @ldap_modify \n"
      if ( $opt{verbose} and @ldap_modify );

}

sub proc_shadowInactive {
    push( @ldap_modify, ( 'shadowInactive', $opt{shadowInactive} ) );
    print "\$opt{shadowInactive}: " . $opt{shadowInactive} . "\n"
      if ( $opt{verbose} );
}

sub proc_shadowWarning {
    push( @ldap_modify, ( 'shadowWarning', $opt{shadowWarning} ) );
    print "\$opt{shadowWarning}: " . $opt{shadowWarning} . "\n"
      if ( $opt{verbose} );
}

sub proc_shadowMax {
    push( @ldap_modify, ( 'shadowMax', $opt{shadowMax} ) );
    print "\$opt{shadowMax}: " . $opt{shadowMax} . "\n" if ( $opt{verbose} );
}

sub proc_shadowMin {
    push( @ldap_modify, ( 'shadowMin', $opt{shadowMin} ) );
    print "\$opt{shadowMin}: " . $opt{shadowMin} . "\n" if ( $opt{verbose} );
}

sub proc_shadowLastChange {
    $opt{shadowLastChange} = from_date_to_int( $opt{shadowLastChange} );
    print "\$opt{shadowLastChange}: " . $opt{shadowLastChange} . "\n"
      if ( $opt{verbose} );
    push( @ldap_modify, ( 'shadowLastChange', $opt{shadowLastChange} ) );

}

sub proc_shadowExpire {
    $opt{shadowExpire} = from_date_to_int( $opt{shadowExpire} );
    print "\$opt{shadowExpire}: " . $opt{shadowExpire} . "\n"
      if ( $opt{verbose} );
    push( @ldap_modify, ( 'shadowExpire', $opt{shadowExpire} ) );
}

sub proc_rootbinddn {
    print "DN: " . $ldap{rootbinddn} . "\n" if ( $opt{debug} );
    print "Password: ";
    ReadMode('noecho');
    $ldap{rootbinddnpw} = ReadLine(0);
    ReadMode('restore');
    chomp( $ldap{rootbinddnpw} );
    print "\n";
    print "\$ldap{rootbinddnpw}: " . $ldap{rootbinddnpw} . "\n"
      if ( $opt{debug} );
}

sub find_ldap_auto_config {
    foreach my $ldapfile (@ldapfile_r) {
        if ( ( -e $ldapfile ) && ( -r $ldapfile ) ) {
            $ldap{ldapfile} = $ldapfile;
            last;
        }
    }

    print "Arquivo de configuração LDAP " . $ldap{ldapfile} . "\n"
      if ( $opt{debug} );
    if ( $ldap{ldapfile} ) {
        open( CONFIG, '<', $ldap{ldapfile} ) or die;
        while (<CONFIG>) {
            chomp;       # no newline
            s/#.*//;     # no comments
            s/^\s+//;    # no leading white
            s/\s+$//;    # no trailing white
            next unless length;    # anything left?
            my ( $var, $value ) = split( /\s/, $_, 2 );
            $ldap{$var} = $value;
            print "\$ldap{$var}: $value\n" if ( $opt{debug} );
        }
        close(CONFIG);
    }
    foreach my $ldapsecret (@ldapsecret_r) {
        if ( ( -e $ldapsecret ) && ( -r $ldapsecret ) ) {
            $ldap{ldapsecret} = $ldapsecret;
            last;
        }
    }
    print "ldapsecret: " . $ldap{ldapsecret} . "...\n" if ( $opt{debug} );
    if ( $ldap{ldapsecret} ) {
        open( LDAPPASS, '<', $ldap{ldapsecret} ) or die;
        $ldap{rootbinddnpw} = <LDAPPASS>;
        chomp( $ldap{rootbinddnpw} );
        close(LDAPPASS);
        print "\$ldap{rootbinddnpw}: [" . $ldap{rootbinddnpw} . "]\n"
          if ( $opt{debug} );
    }
}

sub usage {
    my $message = $_[0];
    if ( defined $message && length $message ) {
        $message .= "\n"
          unless $message =~ /\n$/;
    }

    my $command = $0;
    $command =~ s#^.*/##;

    print STDERR (
        $message,
        "Uso: $command [opções] usuário [usuário ...]

Opções:
  -b, --basedn - Base DN do LDAP
  -d, --lastday ÚLTIMO_DIA - define última mudança de senha
  -D, --binddn DN - Conta com permissão no diretório para realizar a operação
  -E, --expiredate DATA_EXPIRAÇÂO - define data de expiração de senha
  -h, --help - exibe esta mensagem de ajuda e finaliza
  -H, --host - Servidor LDAP
  -I, --inactive - INATIVO Dias após a expiração da senha que a conta se tornará inativa
  -l, --list - exibe informação sobre a conta
  -m, --mindays MIN_DIAS - números mínimo de dias antes da troca de senha
  -M, --maxdays MAX_DIAS - números máximo de dias para a troca de senha 
  -W, --warndays AVISO_DIAS dias para aviso antes da expiração da senha   
"
    );

}

sub ldap_bind {
    if ( $ldap{uri} ) {
        $ldap = Net::LDAP->new( $ldap{uri} ) or die "$@";
    }
    if ( $ldap{rootbinddn} and $ldap{rootbinddnpw} ) {
        $mesg =
          $ldap->bind( $ldap{rootbinddn}, password => $ldap{rootbinddnpw} );
    }
    else {
        print "Bind anônimo, provavlemnte não irá funcionar!\n";
        $mesg = $ldap->bind;
    }

}

sub ldap_unbind {
    $mesg = $ldap->unbind;
}

sub set_ldap_user_configs {
    my $user = shift;

    get_user_information($user);

    #Deveria pegar $mesg de get_user_information()
    if ( $mesg->count > 0 ) {
        my $entry = $mesg->entry(0);
        $entry->replace(@ldap_modify);
        $entry->update($ldap);
    }
    else {
        print "Usuário: $user não existe!\n";
    }

}

sub get_user_information {
    my $user = shift;
    $mesg = $ldap->search(
        base   => $ldap{base},
        filter => "(&(objectClass=PosixAccount)(uid=$user))",
        attrs  => [
            'dn',            'uid',
            'cn',            'shadowLastChange',
            'shadowExpire',  'shadowInactive',
            'shadowWarning', 'shadowMin',
            'shadowMax',     'shadowInactive',
        ],

    );

    #    return \$mesg;
}

sub print_user_information {
    my $user = shift;
    get_user_information($user);

    while ( my $entry = $mesg->shift_entry ) {
        print "-" x 72;
        print "\n";
        print "Minimum:\t\t" . $entry->get_value('shadowMin') . "\n";
        print "Maximum:\t\t" . $entry->get_value('shadowMax') . "\n";
        print "Warning:\t\t" . $entry->get_value('shadowWarning') . "\n";
        print "Inactive:\t\t" . $entry->get_value('shadowInactive') . "\n";
        print "Last Change:\t\t"
          . from_int_to_date( $entry->get_value('shadowLastChange') ) . "\n";
        print "Password Expires:\t"
          . from_int_to_date( $entry->get_value('shadowLastChange') +
              $entry->get_value('shadowMax') )
          . "\n";
        print "Password Inactive:\t"
          . from_int_to_date( $entry->get_value('shadowLastChange') +
              $entry->get_value('shadowMax') +
              $entry->get_value('shadowInactive') )
          . "\n";
        print "Account Expires:\t"
          . from_int_to_date( $entry->get_value('shadowExpire') ) . "\n";
        print "\n";

    }

}

sub from_date_to_int {
    my $date = shift;

    unless ( $date =~ m/(\d{4})-(\d{2})-(\d{2})/ ) {
        usage("Data Inválida, deve ser YYYY-MM-DD");
        exit 1;
    }

    my $int_date = int( timelocal( 0, 0, 0, $3, $2 - 1, $1 ) / 86400 );
    return $int_date;
}

sub from_int_to_date {
    my $int_date = shift;
    if ( !defined($int_date) ) {
        $int_date = 0;
    }
    my $date = strftime( "%b %e, %Y", localtime( ( 1 + $int_date ) * 86400 ) );

    return $date;
}


