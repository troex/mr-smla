<?php
//error_reporting(0);
error_reporting(E_ALL & ~E_NOTICE);

// SendMail Log Analyzer webface
// by Troex Nevelin

//foreach (glob("meta/*") as $filename) {
//   echo "$filename size " . filesize($filename) . "<br>";
//}

echo '<html>'
	. '<head>'
	. '<title>MR.smla - MRtech Sendmail Log Analyzer</title>'
	. '<link rel="stylesheet" type="text/css" href="style.css" />'
	. '</head>'
	. '<body>';
echo '<div style="color: #0033ff; background-color: #abcdef; font-size: 18px; font-weight: bold; border: solid 1px black;">&nbsp;MRtech.<i style="color: #ff0000; font-size: 15px;">smla</i><i style="color: #666; font-size: 10px;"> (sendmail log analyzer)</i><small style="float: right; color: #000000;">v0.3.0 (beta)</small></div>';
if (!($_GET['id'])) {
	echo '<form method="post"><table><tr><td>FROM: </td>'
		. '<td><input type="text" name="from" value="'.(($_POST['from']) ? $_POST['from'] : '*').'" size="24" maxlength="64" /></td></tr>'
		. '<tr><td>TO: </td>'
		. '<td><input type="text" name="to" value="'.(($_POST['to']) ? $_POST['to'] : '*').'" size="24" maxlength="64" /></td></tr>'
		. '<tr><td>DATE: </td><td>'
		. '<select name="month1">'.gen_month(1).'</select>'
		. '<select name="day1">'.gen_date(1, -3).'</select> - '
		. '<select name="month2">'.gen_month(2).'</select>'
		. '<select name="day2">'.gen_date(2).'</select>'
		. '</td></tr>'
		. '<tr><td>SHOW: </td>'
		. '<td><input type="text" name="count" value="'.(($_POST['count']) ? $_POST['count'] : '25').'" size="3" maxlength="3" />'
		. 'RECORDS, FROM <input type="text" name="count2" value="'.(($_POST['count2']) ? $_POST['count2'] : '0').'" size="5" maxlength="5" /></td></tr>'
		. '<tr><td>TYPE: </td><td>'
		. '<input type="checkbox" name="send" value="1" '.(($_POST['send']) ? 'checked ' : '').'/>send&nbsp;&nbsp;&nbsp;'
		. '<input type="checkbox" name="spam" value="1" '.(($_POST['spam']) ? 'checked ' : '').'/>spam&nbsp;&nbsp;&nbsp;'
		. '<input type="checkbox" name="virus" value="1" '.(($_POST['virus']) ? 'checked ' : '').'/>virus<br />'
		. '<input type="checkbox" name="canceled" value="1" '.(($_POST['canceled']) ? 'checked ' : '').'/>canceled&nbsp;&nbsp;&nbsp;'
		. '<input type="checkbox" name="unknown" value="1" '.(($_POST['unknown']) ? 'checked ' : '').'/>unknown'
		. '</td></tr>'
		. '<tr><td colspan="2"><input type="submit" name="search" value="search" /></td></tr></table>'
		. '</form>';
}
if ($_POST['search']) {

	$date1 = date('Y').$_POST['month1'].$_POST['day1'];
	$date2 = date('Y').$_POST['month2'].$_POST['day2'];
	if ($date2 < $date1) {
		$tmp = $date1;
		$date1 = $date2;
		$date2 = $tmp;
	}
	$date1 .= '000000';
	$date2 .= '999999';
	echo 'pattern from: <b>'.$_POST['from'].'</b><br />';
	echo 'pattern to: <b>'.$_POST['to'].'</b><br />';
//	echo 'date1: <b>'.$date1.'</b><br />';
//	echo 'date2: <b>'.$date2.'</b><br />';

	$meta = array();
	$i = $send = $spam = $canceled = $virus = $unknown = 0;
	
	$min = $_POST['count2'];
	$max = $min + $_POST['count'];

	if (($_POST['from'] == '') || ($_POST['from'] == '*')) {
		$static_from = 1;
	} else {
		$pattern_from = '/from=(\<|)'.convernt_preg($_POST['from']).'/i';
		$static_from = 0;
	}
	if (($_POST['to'] == '') || ($_POST['to'] == '*')) {
		$static_to = 1;
	} else {
		$pattern_to = '/to=(\<|)'.convernt_preg($_POST['to']).'/i';
		$static_to = 0;
	}

	//echo "static from:$static_from to:$static_to<br />";
	if (($static_from == 1) && ($static_to == 1)) {
		exit;
	}
				
	foreach (glob('meta/*.cdb') as $file) {
		$ffile = preg_replace('/(^.*\/)|(\..*$)/', '', $file);
		//echo $ffile."<br>";
		list($tmp_file, $file_date) = split('_', $ffile, 2);
		list($file_date1, $file_date2) = split('-', $file_date, 2);
		if (($file_date1 > $date2) or ($file_date2 < $date1)) {
			continue;
		}
		if ($db = dba_open($file, 'r', 'cdb')) {
			$key = dba_firstkey($db);
			while ($key) {
				$line = dba_fetch($key, $db);
				
				list($s2, $s3) = split('\|', $line, 2);
				
				if (($s2 < $date1) or ($s2 > $date2)) {
					$key = dba_nextkey($db);
					continue;
				}
				
				$array = array();
				$array = split('\|', $s3);
				$is_from = 0;
				$is_to = 0;
				if ($static_from == 1) { $is_from = 1; }
				if ($static_to == 1) { $is_to = 1; }
				
				foreach ($array as $blk) {
					if ($is_from == 0) {
						if (preg_match($pattern_from, $blk)) {
							$is_from = 1;
							continue;
						}
					}
					if ($is_to == 0) {
						if (preg_match($pattern_to, $blk)) {
							$is_to = 1;
							continue;
						}
					}
				}
				// COLORS
				// send = green = 1;
				// spam = red = 2;
				// canceled = red2 = 3;
				// virus = red3 = 4;
				// unknown = gray = 5;
				if (($is_from == 1) and ($is_to == 1)) {
					if (preg_match('/(reject\=)|(stat\=Blocked)/', $s3)) {
					   $spam++;
						$color = 2;
					} elseif (preg_match('/stat\=Sent/', $s3)) {
						$send++;
						$color = 1;
					} elseif (preg_match('/stat\=(User\sunknown|Deferred\:|timeout\swaiting)/', $s3)) {
						$canceled++;
						$color = 3;
					} elseif (preg_match('/stat\=virus/', $s3)) {
						$virus++;
						$color = 4;
					} else {
						$unknown++;
						$color = 5;
					}
					$add = 0;
					if (($_POST['send'] == 1) and ($color == 1)) { $add = 1; }
					elseif (($_POST['spam'] == 1) and ($color == 2)) { $add = 1; }
					elseif (($_POST['canceled'] == 1) and ($color == 3)) { $add = 1; }
					elseif (($_POST['virus'] == 1) and ($color == 4)) { $add = 1; }
					elseif (($_POST['unknown'] == 1) and ($color == 5)) { $add = 1; }
					//else { continue; }
					if ($add == 1) {
						$line = $s2.'|'.$color.'|'.$key.'|'.$s3;
						$line = str_replace('<', '&lt;', $line);
						$line = str_replace('>', '&gt;', $line);
						array_push($meta, $line);
					}
				}
				$key = dba_nextkey($db);
			}
			dba_close($db);;
		}
	}

	sort($meta);
	echo 'results found: <b>'.($send+$spam+$virus+$canceled+$unknown).'</b><br />'
		. 'send: <b>'.$send.'</b><br />'
		. 'spam: <b>'.$spam.'</b><br />'
		. 'virus: <b>'.$virus.'</b><br />'
		. 'canceled: <b>'.$canceled.'</b><br />'
		. 'unknown: <b>'.$unknown.'</b><br />';
		
	foreach ($meta as $line) {
		$i++;
		if (($i >= $min) and ($i <= $max)) {
			echo format_meta($i, $line);
		}
		if ($i > $max) { break; }
	}


}

if ($_GET['id']) {
	$found = 0;
	list($id, $time) = split(' ', $_GET['id'], 2);
	//echo "id: $id<br>time: $time<br>";
	echo '<br />message id: <b>'.$id.'</b><br />';
	foreach (glob('logs/*.cdb') as $file) {
		$ffile = preg_replace('/(^.*\/)|(\..*$)/', '', $file);
		//echo 'logfile: '.$ffile."<br>";
		list($tmp_file, $file_date) = split('_', $ffile, 2);
		list($file_date1, $file_date2) = split('-', $file_date, 2);
		if (!(($file_date1 <= $time) and ($file_date2 >= $time))) {
			continue;
		}
		if ($db = dba_open($file, 'r', 'cdb')) {
			$line = dba_fetch($id, $db);
			dba_close($db);
			$line = str_replace('<', '&lt;', $line);
			$line = str_replace('>', '&gt;', $line);
			$array = array();
			$array = split('\|', $line);
			foreach ($array as $line) {
				if ($line == "") { continue; }
				echo '<div id="meta"><tt>';
				echo $line.'<br />';
				echo '</tt></div>';
				$found = 1;
			}
			break;
		}
	}
	if ($found == 0) {
		echo '<div style="background-color: #fcc; margin: 10px; padding: 10px; border: 1px solid black;">sorry message log not found, wrong ID? or it could be deleted due to of time</div>';
	}
	echo '<br /><a href="javascript:window.close();">close</a>';
}

echo '</body></html>';

function format_meta($i, $line) {
	list($time, $color, $id, $meta) = split('\|', $line, 4);
	$array = array();
	$array = split('\|', $meta);
	if ($color == 1) { $c = '#cfc'; }
	elseif ($color == 2) { $c = '#fcc'; }
	elseif ($color == 3) { $c = '#ffc'; }
	elseif ($color == 4) { $c = '#f99'; }
	else { $c = '#ddd'; }
	$ret = '<div id="meta" style="background-color: '.$c.';"><b>'.$i.'</b><br /><small>('.meta_date($time).')</small> <a href="?id='.$id.'+'.$time.'" target="_blank">'.$id.'</a><br /><pre>';
	foreach ($array as $line) {
		$ret .= '&nbsp;&nbsp;&nbsp;'.$line.'<br />';
	}
	$ret .= '</pre></div><br />';
	return $ret;
}

function meta_date($date) {
	return preg_replace('/(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/', '$1-$2-$3 $4:$5:$6', $date);
}

function loadmeta($path) {
	$meta = array();
	foreach (glob($path) as $file) {
		if ($handle = fopen($file, 'r')) {
			while (!feof($handle)) {
				$buffer = fgets($handle);
				array_push($meta, $buffer);
			}
			fclose($handle);
		}
	}
	return $meta;
}

function convernt_preg($preg) {
	$preg = str_replace('.', '\.', $preg);
	$preg = str_replace('*', '.*', $preg);
	$preg = str_replace('@', '\@', $preg);
	return $preg;
}

function gen_date($pd, $m = null) {
	$d = date('j');
	$ret = "";
	if ($m) {
		$d += $m;
		if ($d < 1) {
			$d = 1;
		}
	}
	$pd = 'day'.$pd;
	if ($_POST[$pd]) {
		$d = $_POST[$pd];
	}
	if ($d < 10) {
		$d = '0'.$d;
	}
	for ($i = 1; $i <= 31; $i++) {
		$j = $i;
		if ($i < 10) {
			$j = '0'.$j;
		}
		if ($d == $j) {
			$sel = ' selected';
		} else {
			$sel = '';
		}
	 	$ret .= '<option value="'.$j.'"'.$sel.'>'.$j.'</option>';
	}
	return $ret;
}

function gen_month($pm) {
	$m = date('m');
	$pm = 'month'.$pm;
	if ($_POST[$pm]) {
		$m = $_POST[$pm];
	}
	$month = '<option value="01">Jan</option>'
		. '<option value="02">Feb</option>'
		. '<option value="03">Mar</option>'
		. '<option value="04">Apr</option>'
		. '<option value="05">May</option>'
		. '<option value="06">Jun</option>'
		. '<option value="07">Jul</option>'
		. '<option value="08">Aug</option>'
		. '<option value="09">Sep</option>'
		. '<option value="10">Oct</option>'
		. '<option value="11">Nov</option>'
		. '<option value="12">Dec</option>';
	$month = str_replace('="'.$m.'">', '="'.$m.'" selected>', $month);
	return $month;
}

?>
