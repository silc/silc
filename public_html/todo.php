<br>
<tt>
<font face="courier" size="3">
<?php

if (File_exists($DocRoot."todo.txt"))
  if ($fp = @FOpen($DocRoot."todo.txt", "r")) {
  
  while($line = FGets($fp, 255)) {
    $newline = Ereg_Replace("^[ ]{2,4}","&nbsp;&nbsp;",$line);
    $line = Ereg_Replace("^([\t]|[ ][\t])","&nbsp;&nbsp;&nbsp;&nbsp;",$newline);
    printf("%s", nl2br($line));
  }

  FClose($fp);
  }
?>
</font>
</tt>
<br>
