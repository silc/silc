&nbsp;<br />
<tt class="black">
<?php

if (Is_Readable("txt/todo.txt")) {
  $fp = FOpen("txt/todo.txt", "r");

  while($line = FGets($fp, 255)) {
    $newline = Ereg_Replace("^[ ]{2,4}","&nbsp;&nbsp;",$line);
    $line = Ereg_Replace("^([\t]|[ ][\t])","&nbsp;&nbsp;&nbsp;&nbsp;",$newline);
    printf("%s", nl2br($line));
  }

  FClose($fp);
  }
?>
</tt>
