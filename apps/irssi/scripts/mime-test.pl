use Irssi;
use MIME::Base64;

sub sig_mime {

  my ($server, $channel, $blob, $enc, $type, $nick) = @_;

  Irssi::print("$enc - $type - $blob->{octets}");

  if (($enc eq "base64") && ($type eq "image/png")) {
    # just stores the image in /tmp/$nick.png
    open OFILE, '>', "/tmp/" . $nick . ".png";
    print OFILE decode_base64($blob->{data});
    close OFILE;
    Irssi::signal_stop();
  }

}

sub cmd_scribble {

  my ($data, $server, $channel) = @_;

  return if $server->{chat_type} !~ /^silc$/i;

  # let's hope, $data is a png image...
  open IFILE, $data;

  read IFILE, $image, 0xffff;

  close IFILE;

  $data = encode_base64($image);
  $octets = length($data);
  Irssi::print($octets);

  Irssi::signal_emit("mime-send", $server, $channel, $data, \$octets,
  	"base64", "image/png");
}

Irssi::signal_add("mime", "sig_mime");
# /scribble path/to/image.png
Irssi::command_bind("scribble", "cmd_scribble");
