<?php
//test 2

function Hits() {

// $datafile has to be writable by http server user uid
// else hits count will not be increased, only printed out

  $datafile = $DocRoot."COUNTER";

  if (Is_Writable($datafile)) {
    $fp = FOpen($datafile, "r+");
    $writable = "true";
  }
  else
    if (Is_Readable($datafile)) $fp = FOpen($datafile,"r");
    else return;
  
  $hits = FGets($fp,255) + 1;
  if(!$hits) $hits = 1;

  if($writable) {
    Rewind($fp);
    FPuts($fp, $hits);
  }

  FClose($fp);
  echo $hits." hits";
}

Hits();

?>

$Id$
