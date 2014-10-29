use strict;
use warnings;
use feature qw(say);
use WWW::Wappalyzer;
use LWP::UserAgent;

my $uri = shift;
my $debug = 0;
die "Usage: perl $0 <url> \n" unless defined($uri);

chomp $uri;

my $host =  $1 if $uri =~ /(?:https?:\/\/)?([\w.-]+)/;


my $browser = LWP::UserAgent->new();
my $UserAgent = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:12.0) Gecko/20100101 Firefox/12.0";
my $timeout = 180;
my $redirect = 30;
$browser->agent($UserAgent);
$browser->timeout($timeout);
$browser->ssl_opts(verify_hostname => 1);
$browser->max_redirect($redirect);
$browser->show_progress(1) if $debug == 1;
$browser->default_header('Accept'=>'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8');
$browser->default_header('Accept-Encoding'=>'gzip,deflate,sdch');
$browser->default_header('Connection' => 'keep-alive');
$browser->default_header('Host' => $host) if $host;	



$uri = 'http://'.$uri unless($uri =~ /https?:\/\/([^\/\\]+)/);
    
my $response = $browser->get($uri);


if($debug == 1){
say $response->request->as_string;
say "\n";
say $response->headers_as_string;
}


my %detected = WWW::Wappalyzer::detect(
    html    => $response->decoded_content,
    headers => $response->headers,
);

foreach (keys %detected){
	my $tmp = $detected{$_};
	my @details = @$tmp;
	print $_,": [";
	my $str = qw();
	map { $str .= "\"$_\"".",";} @details;
	chop $str;
	say $str."]";
}

