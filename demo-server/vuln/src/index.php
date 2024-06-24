<?php

if (isset($_GET['payload'])) {
    echo 'Your payload is: ' . $_GET['payload'];
} else {
    echo 'Welcome!';
}

?>