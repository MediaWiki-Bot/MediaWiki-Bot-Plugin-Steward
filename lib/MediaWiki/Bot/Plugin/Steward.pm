package MediaWiki::Bot::Plugin::Steward;
use locale;
use POSIX qw(locale_h);
setlocale(LC_ALL, "en_US.UTF-8");
use strict;

our $VERSION = '0.2.1';

=head1 NAME

MediaWiki::Bot::Plugin::Steward

=head1 SYNOPSIS

use MediaWiki::Bot;

my $editor = MediaWiki::Bot->new('Account');
$editor->login('Account', 'password');

=head1 DESCRIPTION

MediaWiki::Bot is a framework that can be used to write Wikipedia bots.

=head1 AUTHOR

The Perlwikipedia team

=head1 METHODS

=over 4

=item import()

Calling import from any module will, quite simply, transfer these subroutines into that module's namespace. This is possible from any module which is compatible with MediaWiki/Bot.pm.

=cut

sub import {
	no strict 'refs';
	foreach my $method (qw/sample_steward/) {
		*{caller() . "::$method"} = \&{$method};
	}
}

=item sample_steward($arg)


=cut

sub sample_steward {
	my $self    = shift;

	return;
}

1;

