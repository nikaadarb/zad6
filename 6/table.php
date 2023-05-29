<head>
  <link rel="stylesheet" href="style.css" type="text/css">
</head>
<style>
  table {
  text-align: center;
  border-spacing: 100px 0;
}
</style>
<body>
  <div class="table">
    <table>
      <tr>
        <th>Имя</th>
        <th>Электронная почта</th>
        <th>День рождения</th>
        <th>Пол</th>
        <th>Количество конечностей</th>
        <th>Суперспособности</th>
        <th>Био</th>
      </tr>
      <?php
      foreach($users as $user){
      ?>
            <tr>
              <td><?= $user['name']?></td>
              <td><?= $user['email']?></td>
              <td><?= $user['year']?></td>
              <td><?= $user['pol']?></td>
              <td><?= $user['limbs']?></td>
              <td><?php 
                $user_ability=array(
                    "1"=>FALSE,
                    "2"=>FALSE,
                    "3"=>FALSE,
					"4"=>FALSE
                );
                foreach($pwrs as $pwr){
                    if($pwr['per_id']==$user['id']){
                        if($pwr['name_id']=='1'){
                            $user_ability['1']=TRUE;
                        }
                        if($pwr['name_id']=='2'){
                            $user_ability['2']=TRUE;
                        }
                        if($pwr['name_id']=='3'){
                            $user_ability['3']=TRUE;
                        }
						if($pwr['name_id']=='4'){
                            $user_ability['4']=TRUE;
                        }
                    }
                }
				if($user_ability['1']){echo 'ничего<br>';}
                if($user_ability['2']){echo 'умение летать<br>';}
                if($user_ability['3']){echo 'умение читать мысли<br>';}
                if($user_ability['4']){echo 'бессмертие<br>';}?>
              </td>
              <td><?= $user['bio']?></td>
              <td>
                <form method="get" action="edit.php">
                  <input name=edit_id value="<?= $user['id']?>" hidden>
                  <input type="submit" value=Edit>
                </form>
              </td>
            </tr>
      <?php
       }
      ?>
    </table>
    <?php
	printf('ничего: %d <br>',$ability_count[0]);
    printf('умение летать: %d <br>',$ability_count[1]);
    printf('умение читать мысли: %d <br>',$ability_count[2]);
    printf('бессмертие: %d <br>',$ability_count[3]);
    ?>
  </div>
</body>