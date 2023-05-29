<?php
header('Content-Type: text/html; charset=UTF-8');
session_start();
if ($_SERVER['REQUEST_METHOD'] == 'GET') {
  if (!empty($_SESSION['login'])) {
  header('Location: index.php');
  }else{
?>
<div class="form-sign-in">
<form action="login.php" method="post">
  <label> Логин <label> <br>
  <input name="login" /> <br> 
  <label> Пароль <label> <br>
  <input name="password" type="password"/> <br><br>
  <input type="submit" value="Войти" />
</form>
</div>
<?php
  }
}
else {
  $login=$_POST['login'];
  $password=$_POST['password'];
  $uid=0;
  $error=TRUE;
  $user = 'u52828';
  $pass = '9210682';
  $db1 = new PDO('mysql:host=localhost;dbname=u52828', $user, $pass, array(PDO::ATTR_PERSISTENT => true));
  if(!empty($login) and !empty($password)){
    try{
      $chk=$db1->prepare("select * from users where login=?");
      $chk->bindParam(1,$login);
      $chk->execute();
      $username=$chk->fetchALL();
	  var_dump($username);
      if(password_verify($password,$username[0]['passwrld'])){
        $uid=$username[0]['id'];
        $error=FALSE;
      }
    }
    catch(PDOException $e){
      print('Error : ' . $e->getMessage());
      exit();
    }
  }
  if($error==TRUE){
    print('Неправильные логин или пароль <br> Если вы хотите создать нового пользователя <a href="index.php">назад</a> или попытайтесь войти снова <a href="login.php">войти</a>');
    session_destroy();
    exit();
  }
  // Если все ок, то авторизуем пользователя.
  $_SESSION['login'] = $login;
  // Записываем ID пользователя.
  $_SESSION['uid'] = $uid;
  // Делаем перенаправление.
  header('Location: index.php');
}