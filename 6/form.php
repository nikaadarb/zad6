<!DOCTYPE html>
<html lang="en">
<head>
    <meta content="text/html;charset=utf-8" http-equiv="Content-Type">
    <title>Task 6	</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<?php
if (!empty($messages)) {
  print('<div id="messages">');
  foreach ($messages as $message) {
    print($message);
  }
  print('</div>');
}
?>

<div id = "form">

  <form action="index.php"
    method="POST">

    <label>
      Имя:<br />
      <input name="name"
      <?php print($errors['name'] ? 'class="error"' : '');?> value="<?php print $values['name'];?>"/>
    </label><br />

    <label >
      Эл почта:<br />
      <input name="email"
        type="email"
        <?php print($errors['email'] ? 'class="error"' : '');?> value="<?php print $values['email'];?>"/>
    </label><br />

    <label>
      День рождения<br />
      <select name="year">
        <?php 
        for ($i = 500; $i <= 2023; $i++) {
          $selected= ($i == $values['year']) ? 'selected="selected"' : '';
          printf('<option value="%d" %s>%d год</option>', $i, $selected, $i);
        }
        ?>
      </select><br />

      Пол<br/>
    <label><input type="radio" checked="checked"
      name="pol" value="m" 
      <?php print($errors['pol'] ? 'class="error"' : '');?>
      <?php if ($values['pol']=='m') print 'checked';?>
      />
      Мужской</label>
    <label><input type="radio"
      name="pol" value="f" 
      <?php print($errors['pol'] ? 'class="error"' : '');?>
      <?php if ($values['pol']=='f') print 'checked';?>
      />
      Женский</label><br />
      Конечностей<br/>
    <label><input type="radio" checked="checked"
      name="limb" value="1" 
      <?php print($errors['limb'] ? 'class="error"' : '');?>
      <?php if ($values['limb']=='1') print 'checked';?>
      />
      1</label>
    <label><input type="radio"
      name="limb" value="2" 
      <?php print($errors['limb'] ? 'class="error"' : '');?>
      <?php if ($values['limb']=='2') print 'checked';?>
      />
      2</label><br />
    <label><input type="radio"
      name="limb" value="3" 
      <?php print($errors['limb'] ? 'class="error"' : '');?>
      <?php if ($values['limb']=='3') print 'checked';?>
      />
      3</label><br />
    <label>
      Суперспособность
      <br />
      <select name="ability[]"
          multiple="multiple" <?php print($errors['ability'] ? 'class="error"' : '');?>>
          <option value="1" <?php print(in_array('1', $values['ability']) ? 'selected ="selected"' : '');?>>ничего</option>
          <option value="2" <?php print(in_array('2', $values['ability']) ? 'selected ="selected"' : '');?>>умение летать</option>
          <option value="3" <?php print(in_array('3', $values['ability']) ? 'selected ="selected"' : '');?>>умение читать мысли</option>
          <option value="4" <?php print(in_array('4', $values['ability']) ? 'selected ="selected"' : '');?>>бессмертие</option>
      </select>
      </label><br />
      <label>
      Биография<br />
        <textarea name="bio"
        <?php print($errors['bio'] ? 'class="error"' : '');?>><?php print $values['bio'];?></textarea>
        </label><br />
        
      <label><input type="checkbox"
        name="check" />
        Ознакомился</label>

      <input type="submit" value="отправить" />
    </form>
	 <?php
  if(empty($_SESSION['login'])){
   echo'
   <div class="login">
    <p>Если у вас есть аккаунт, вы можете <a href="login.php">войти</a></p>
   </div>';
  }
  else{
    echo '
    <div class="logout">
      <form action="index.php" method="post">
        <input name="logout" type="submit" value="Выйти">
      </form>
    </div>';
  } ?>
  </div>
</body>