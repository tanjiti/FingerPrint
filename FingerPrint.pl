use strict;
use warnings;
use feature qw(say);
use WWW::Wappalyzer qw(detect get_categories add_clues_file);
use LWP::UserAgent;
use Devel::Peek qw(Dump);
my $uri = shift;
my $rulefile = shift;
my $debug = 0;
die "Usage: perl $0 <url|urllistFile> [rulefile]\n" unless defined($uri);


chomp $uri;
chomp $rulefile if $rulefile;

########################################################
# main progress
########################################################
if(-e $uri){

	 multiURL($uri,$rulefile);
	
}else{
        my $result = getFP($uri,$rulefile);
        say "{";
        print $result;
        say "}";

}


###########################################################
#--! multiURL: get multi url of url file finger print 
#--! parma: urlfile, rulefile
#--! return: fingerprint result json file
##########################################################

sub multiURL{
	my ($file,$rulefile) = @_;
	
	die "$file not exists or 0-size \n" unless -e $file and -s $file;
	
	my $tmp_file = $file."_tmp";
	#uniq and clear Blank lines
	`cat $file |sort|uniq|sort|grep -v "^\$">$tmp_file && mv $tmp_file $file `;
	die "uniq clear blank lines failed ! \n" if $? != 0;
	
	
	my $file_out = $uri."_fingerprint";
	open my $IN, "<:encoding(UTF-8)", $file or die "cannot open $file for reading \n";
	open my $OUT, ">:encoding(UTF-8)", $file_out or die "cannot open $file_out for writing \n";
	
	my $line_number = `cat $file | wc -l`;
	die "get $file record number failed ! \n" if $? != 0;
	chomp $line_number;

	say $OUT "{";
	my $index = 1;
	while(<$IN>){

		last if $index > $line_number -1 ;
		chomp;
		my $result_per_url = getFP($_,$rulefile);

		chomp $result_per_url;
		$result_per_url .= ",";

		say $OUT $result_per_url;

		$index++;	
	}
	
	my $last_host = `tail -1 $file`;
	chomp $last_host;
	my $result_per_url = getFP($last_host,$rulefile);
	print $OUT $result_per_url;	

	say $OUT "}";
	close $IN;
	close $OUT;

}




###########################################################
#--! sendHTTP: send http request and return response object
#--! param: uri
#--! return: response hash object
##########################################################
sub sendHTTP{
	my $uri = shift;
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
	return $response;
}

############################################################
#--! getFP: get finger print result
#--! param: url,rulefile 
#--! return: finger print json result
###########################################################
sub getFP{
	
	my ($url,$rule_file) = @_;
	my $response = sendHTTP($url);
	
	#add your new finger print rule json file
	add_clues_file($rulefile) if $rulefile and  -e $rulefile;


	my %detected = detect(
    		html    => $response->decoded_content,
    		headers => $response->headers,
		url => $uri,
   		# cats => ["cms"],
	);

	my $result = jsonOutput($url,\%detected);
	return $result;
}

############################################################
#--! jsonOutput: output hash result in json format
#--! param: uri, detected_ref
#--! return: json_format string
############################################################
sub jsonOutput{
	my ($uri,$detected_ref) = @_;
	my %detected = %$detected_ref;
	my $str_app_fp = qw();
	$str_app_fp = "\t\"$uri\": {\n";
	foreach (keys %detected){
		my $tmp = $detected{$_};
		my @details = @$tmp;
		$str_app_fp .=  "\t\t\"$_\": [\n";

	
		map {$str_app_fp .= "\t\t\t\"$_\",\n" } @details;

		chop $str_app_fp;
		chop $str_app_fp;
		$str_app_fp .= "\n\t\t],\n";		
	}	

	if (scalar keys %detected > 0){
		chop $str_app_fp;
		chop $str_app_fp;
	}

	
	$str_app_fp .= "\n\t}\n";
	return $str_app_fp;

}
