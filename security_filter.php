<?php
/**
 * 全局安全过滤函数
 * 支持SQL注入和跨站脚本攻击
 */
function global_filter()
{
	//APP，ACT 分别为控制器和控制器方法
	$params = array(APP, ACT);
	foreach($params as $k => $v)
	{
		if(!preg_match("/^[a-zA-Z0-9_-]+$/", $v))
		{
            header_status_404();
		}
	}
	
	$arrStr = array('%0d%0a', "'", '<', '>', '$', 'script', 'document', 'eval','atestu','select','insert?into','delete?from');
	global_inject_input($_SERVER['HTTP_REFERER'], $arrStr, true);
	global_inject_input($_SERVER['HTTP_USER_AGENT'], $arrStr, true);
	global_inject_input($_SERVER['HTTP_ACCEPT_LANGUAGE'], $arrStr, true);
	global_inject_input($_GET, array_merge($arrStr, array('"')), true);
	//global_inject_input($_COOKIE, array_merge($arrStr, array('"', '&')), true);
    //cookie会有对url的记录(pGClX_last_url)。去掉对&的判断
    global_inject_input($_COOKIE, array_merge($arrStr, array('"')), true);
	global_inject_input($_SERVER, array('%0d%0a'), true);

	//处理跨域POST提交问题
	if($_SERVER['REQUEST_METHOD'] == 'POST')
	{
		$url = parse_url($_SERVER['HTTP_REFERER']);
		$referer_host = !empty($url['port']) && $url['port'] != '80' ? $url['host'].':'.$url['port'] : $url['host'];
		if ($referer_host != $_SERVER['HTTP_HOST'])
		{
           header_status_404();
		}
	}
	
	global_inject_input($_POST, array('%0d%0a'));
	global_inject_input($_REQUEST, array('%0d%0a'));
}

/**
 * 全局安全过滤函数
 */
function global_inject_input($string, $inject_string, $replace = false)
{
	if(!is_array($string))
	{
		foreach($inject_string as $value)
		{
			if(stripos(strtolower($string), $value) !== false)
			{
                header_status_404();
			}
		}
		if($replace)
		{
			return filter_var(safe_replace($string),FILTER_SANITIZE_STRING);
		}
		else
		{
		   	return $string;
		}
	}

	foreach($string as $key => $val)
	{
		$string[$key] = global_inject_input($val, $inject_string, $replace);
	}

	return $string;
}

/**
 * http 头信息
**/
function header_status_404($status = '404')
{
   if(substr(php_sapi_name(), 0, 3) == 'cgi')
	{
	   header('Status: '.$status, TRUE);
	   exit;
	}
   else
   {
		header($_SERVER['SERVER_PROTOCOL'].' '.$status);
		$error_404 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n";
		$error_404 .= "<html><head>\r\n";
		$error_404 .= "<title>404 Not Found</title>\r\n";
		$error_404 .= "</head><body>\r\n";
		$error_404 .= "<h1>Object not found!</h1>\r\n";
		$error_404 .= "<p>The requested URL was not found on this server!~</p>\r\n";
		$error_404 .= "<h2>Error 404</h2></body></html>";
		echo $error_404;
		exit;
	}
}

/**
 * 安全过滤函数
 *
 * @param $string
 * @return string
 */
function safe_replace($string)
{
	$string = str_replace('%20', '', $string);
	$string = str_replace('%27', '', $string);
	$string = str_replace('%2527', '', $string);
	$string = str_replace('*', '', $string);
	$string = str_replace('"', '&quot;', $string);
	$string = str_replace("'", '', $string);
	$string = str_replace('"', '', $string);
	$string = str_replace(';', '', $string);
	$string = str_replace('<', '&lt;', $string);
	$string = str_replace('>', '&gt;', $string);
	$string = str_replace("{", '', $string);
	$string = str_replace('}', '', $string);
	return $string;
}
