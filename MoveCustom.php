<?php

# Move clients from the Default group to any other

include("SEPM14API.php");

# AUTH
$api = new SEPM14API("127.0.0.1");
$api->authenticate("admin", 'XXXX');

# MOVE 
$default_group_ID = "HEXHEXHEXHEXHEXHEXHEX"; # Select the group -> right click -> Properties
$clients = $api->call("/groups/".$default_group_ID."/computers?pageSize=100");
$_MOVE = [];

foreach($clients['content'] as $pc){
	$_MOVE[] = [$pc['hardwareKey'],$pc['computerName']];
}

# More than 100 clients in the group ?
if ($clients['totalPages'] != 1){

	echo "Will fetch ".($clients['totalPages']-1)." more page(s)\r\n";

	for($i = 2; $i<=intval($clients['totalPages']);$i++)
	{
		echo " - $i\r\n";
		$clients = $api->call("/groups/".$default_group_ID."/computers?pageSize=100&pageIndex=$i");
		foreach($clients['content'] as $pc){
			$_MOVE[] = [$pc['hardwareKey'],$pc['computerName']];
		}
	}
}

if (count($_MOVE) == 0){
	exit();
}

$api->wait();

$i = 0;
$all = count($_MOVE);

foreach($_MOVE as $pc){

	$i++;
	echo $i." of ".$all."-".$pc[0]."\r\n";

	$api->call("/computers", "PATCH", [[
		"group" => ["id" => "HEXHEXHEXHEXHEXHEXHEX"], # destination group id
		"hardwareKey" => $pc[0]
	]]);
}

$api->logOut();

?>