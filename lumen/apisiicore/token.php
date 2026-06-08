<?php 

if(isset($_POST["rut"])){$rut=$_POST["rut"];}else{$rut=1;}

echo md5( date("Ymd") . "@" . $rut);?>

<form name="otra" id="otra" method="post"> 
<input type="text" name="rut" id=rut value="<?php echo $rut?>">
<input type="submit" value ="mostrar">
</form>
