<?php
header('Content-Type: text/html; charset=UTF-8');
if ($_SERVER['REQUEST_METHOD'] == 'GET') {
  $messages = array();
  if (!empty($_COOKIE['save'])) {
    setcookie('save', '', 100000);
    $messages[] = 'результаты сохранены.';
    setcookie('name', '', 100000);
    setcookie('mail_value', '', 100000);
    setcookie('year_value', '', 100000);
    setcookie('pol_value', '', 100000);
    setcookie('limb_value', '', 100000);
    setcookie('bio_value', '', 100000);
    setcookie('ability', '', 100000);

  }
  //Ошибки
  
  $errors = array();
  $errors['name'] = !empty($_COOKIE['name_error']);
  $errors['email'] = !empty($_COOKIE['email_error']);
  $errors['year'] = !empty($_COOKIE['year_error']);
  $errors['pol'] = !empty($_COOKIE['pol_error']);
  $errors['limb'] = !empty($_COOKIE['limb_error']);
  $errors['ability'] = !empty($_COOKIE['ability_error']);
  $errors['bio'] = !empty($_COOKIE['bio_error']);

  if ($errors['name']) {
    setcookie('name_error', '', 100000);
    $messages[] = '<div class="error">введите имя.</div>';
  }
  if ($errors['email']) {
    setcookie('email_error', '', 100000);
    $messages[] = '<div class="error">введите email.</div>';
  }
  if ($errors['year']) {
    setcookie('year_error', '', 100000);
    $messages[] = '<div class="error">введите год.</div>';
  }
  if ($errors['pol']) {
    setcookie('pol_error', '', 100000);
    $messages[] = '<div class="error">введите пол.</div>';
  }
  if ($errors['limb']) {
    setcookie('limb_error', '', 100000);
    $messages[] = '<div class="error">введите кол-во конечностей.</div>';
  }
  if ($errors['ability']) {
    setcookie('ability_error', '', 100000);
    $messages[] = '<div class="error">введите суперспособность.</div>';
  }
  if ($errors['bio']) {
    setcookie('bio_error', '', 100000);
    $messages[] = '<div class="error">введите биографию.</div>';
  }
  
  $values = array();
  $user = 'u52828';
$pass = '9210682';
$db = new PDO('mysql:host=localhost;dbname=u52828', $user, $pass, array(PDO::ATTR_PERSISTENT => true));
  try{
      $id=$_GET['edit_id'];
	  var_dump($_GET['edit_id']);
      $get=$db->prepare("select * from form where id=?");
      $get->execute(array($id));
      $user=$get->fetchALL();
      $values['name']=$user[0]['name'];
      $values['email']=$user[0]['email'];
      $values['year']=$user[0]['year'];
      $values['pol']=$user[0]['pol'];
      $values['limb']=$user[0]['limbs'];
      $values['bio']=$user[0]['bio'];
      $get2=$db->prepare("select name_id from super where per_id=?");
      $get2->execute(array($id));
      $pwrs=$get2->fetchALL();

	  $temp=array(0=>empty($pwrs[0]['name_id'])?null:$pwrs[0]['name_id'],1=>empty($pwrs[1]['name_id'])?null:$pwrs[1]['name_id'],2=>empty($pwrs[2]['name_id'])?null:$pwrs[2]['name_id'],3=>empty($pwrs[3]['name_id'])?null:$pwrs[3]['name_id']);
      $values['ability'] = $temp;
  }
  catch(PDOException $e){
      print('Error: '.$e->getMessage());
      exit();
  }
  include('editform.php');
}
else {
  if(!empty($_POST['edit'])){
	$id=$_POST['id'];
    $name=$_POST['name'];
    $email=$_POST['email'];
    $year=$_POST['year'];
    $sex=$_POST['pol'];
    $limb=$_POST['limb'];
    $bio=$_POST['bio'];
	$pwrs=$_POST['ability'];
    $user = 'u52828';
$pass = '9210682';
$db = new PDO('mysql:host=localhost;dbname=u52828', $user, $pass, array(PDO::ATTR_PERSISTENT => true));
        $upd=$db->prepare("update form set name=?,email=?,year=?,pol=?,limbs=?,bio=? where id=?");
        $upd->execute(array($name,$email,$year,$sex,$limb,$bio,$id));
        $del=$db->prepare("delete from super where per_id=?");
        $del->execute(array($id));
        $upd=$db->prepare("insert into super set name_id=?,per_id=?");
	  foreach ($pwrs as $ability) {
		$upd->execute([$ability,$id]);
	  }
    
    header('Location: edit.php?edit_id='.$id);
  }
  elseif(!empty($_POST['del'])) {
    $id=$_POST['id'];
    $user = 'u52828';
$pass = '9210682';
$db = new PDO('mysql:host=localhost;dbname=u52828', $user, $pass, array(PDO::ATTR_PERSISTENT => true));
    try {
      $del=$db->prepare("delete from super where per_id=?");
      $del->execute(array($id));
	  $del1=$db->prepare("delete from users where per_id=?");
      $del1->execute(array($id));
      $stmt = $db->prepare("delete from form where id=?");
      $stmt -> execute(array($id));
    }
    catch(PDOException $e){
      print('Error : ' . $e->getMessage());
    exit();
    }
    setcookie('del','1');
    setcookie('del_user',$id);
    header('Location: admin.php');
  }
  else{
    header('Loction: admin.php');
  }
}