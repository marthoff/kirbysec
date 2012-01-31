<?php

define('KIRBYSEC_LOGIN_REQUIRED', 1);
define('KIRBYSEC_ACCESS_DENIED', 2);
define('KIRBYSEC_ACCESS_GRANTED', 3);


// Default for Login Timeout 30 minutes
c::set('kirbysec.timeout', 30 * 60); 

s::start();

// Login
if (r::get('username') && r::get('password') && r::method() == 'POST') 
{
	$username = r::get('username');
	$password = r::get('password');
	$tempuser = Secure::load_user($username);
	if ($tempuser) {
		if (strcmp($tempuser->password, md5($password)) == 0) {
			s::set('kirbysec.uid', $username);
			s::set('kirbysec.ll', time());
			if (r::get('url')) {
				go(r::get('url'));
			}
		}
	}
}

// Logout
if (r::get('logout') == 'now') {
	Secure::logout();
}

class Secure {

	/**
	 * Check access for the current user
	 * 
	 * @param $page
	 *	Current page
	 * @param 
	 *	$roles Specific roles, if NULL check for current page's roles.
	 *
	 * @return
	 *	KIRBYSEC_LOGIN_REQUIRED, if the current user is unkown and a login is required.
	 *	KIRBYSEC_ACCESS_DENIED, if the current user does not satisfy the requested role.
	 *	KIRBYSEC_ACCESS_GRANTED, if the current user satisfies the requested roles or no roles were requested.
	 */
	static function check_access($page, $roles = NULL) {
		$user = self::current_user();
		if ($roles == NULL) {
			$roles = secure::required_roles($page);
		}
		if (!empty($roles)) {
			if (!$user) {
				return KIRBYSEC_LOGIN_REQUIRED;
			} else if (!$user->check_roles($roles)) {
				return KIRBYSEC_ACCESS_DENIED;
			} else if ($user->check_roles($roles)) {
				return KIRBYSEC_ACCESS_GRANTED;
			}
			return KIRBYSEC_ACCESS_DENIED;
		}
		
		return KIRBYSEC_ACCESS_GRANTED;
	}
	
	/**
	 * Creates a logout link
	 */
	static function logout_link($text = 'Logout') {
		return '<a href="' . thisURL() . '?logout=now">' . $text . '</a>';
	}
	
	/**
	 * Logout current user
	 */
	static function logout() {
		s::remove('kirbysec.uid');
	}

	/**
	 * Returns the current user object
	 */
	static function current_user() {
		static $user = NULL;
		$uid = s::get('kirbysec.uid');
		$ll = s::get('kirbysec.ll');
		if (!$ll || time() - $ll < c::get('kirbysec.timeout')) {
			if ($uid) {
				$user = secure::load_user($uid);
				s::set('kirbysec.ll', time());
			}
		}
		return $user;
	}
	
	/**
	 * Load the user object
	 * @param $uid
	 *	User Id
	 */
	static function load_user($uid) {
		$filename = c::get('security.profiles') . '/' . f::safe_name($uid) . '.txt';

		if (file_exists($filename)) {
			$vars = variables::fetch($filename);
			$user = new User($uid, $vars);
			return $user;
		}
		
		return NULL;
	}
	
	/**
	 * Creates a new user
	 *
	 * @param $uid
	 *	User ID of the new user
	 * @param $password
	 *	New password (not decrypted)
	 */
	static function create_user($uid, $password) {
		$filename = self::get_filename($uid);
		if (!file_exists($filename)) {
			$vars = array(
				'Password' => md5($password),
			);
			f::write($filename, self::create_content($vars));
		}
	}
	
	static function get_filename($uid) {
		return c::get('security.profiles') . '/' . f::safe_name($uid) . '.txt';
	}
	
	static function create_content($vars) {
		$result = '';
		foreach ($vars as $k => $v) {
			$result .= str::urlify($k) . ': ' . $v . "\r\n----";			
		}
		return $result;
	}
	
	/**
	 * Returns the roles that are reuqired for the given page
	 */
	static function required_roles($page) {
		$roles = array();
		$p = $page;
		while ($p) {
		  if ($p->requiredroles()) {
			$names = explode(',', $p->requiredroles());
			array_walk($names, 'secure::trim_names');
			$roles[] = $names;
		  }
		  $p = $p->parent();
		}
		return $roles;
	}	

	/* Callback */
	static function trim_names(&$item) {
		$item = mb_strtolower(trim($item), 'UTF-8');
	}
	
}

class User {

	public $rolenames;
	public $uid;
	public $password;
	public $vars = array();
	
	function __construct($uid, $vars) {
		$this->rolenames = $vars['rolenames'];
		$this->uid = $uid;
		$this->password = $vars['password'];
		
		unset($vars['rolenames']);
		unset($vars['password']);
		foreach ($vars as $k => $v) {
			$this->vars[$k] = $v;
		}
	}
	
	function name() {
		return $this->vars['name'];
	}
	
	function roles() {
		$roles = explode(',', $this->rolenames);
		array_walk($roles, 'Secure::trim_names');
		return $roles;
	}
	
	function check_roles($requiredroles) {
		if (!is_array($requiredroles))
			$requiredroles = array($requiredroles);
			
		$userRoles = $this->roles();
		foreach ($requiredroles as $rolesForLevel) {
			$satisfied = FALSE;
			foreach ($rolesForLevel as $role) {
				if (in_array($role, $userRoles)) {
					$satisfied = TRUE;
					continue;
				}
			}
			if (!$satisfied) return FALSE;
		}
		return TRUE;
	}
	
}
