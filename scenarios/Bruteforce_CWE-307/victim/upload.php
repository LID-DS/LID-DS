<?php

$uploaddir = '/var/www/private/uploads/';
$uploadfile = $uploaddir . basename($_FILES['userfile']['name']);

echo '<pre>';
if (move_uploaded_file($_FILES['userfile']['tmp_name'], $uploadfile)) {
    echo "File is valid, and was successfully uploaded.\n";
    } else {
        echo "Error: Please try again!\n";
	}

//echo 'Here is some more debugging info:';
//print_r($_FILES);

print "</pre>";
