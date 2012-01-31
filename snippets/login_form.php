<form action="<?php echo $page->url() ?>" method="post">
	<p>
		<?php echo html($page->username()) ?>
		<input type="text" name="username" />
	</p>
	<p>
		<?php echo html($page->password()) ?>
		<input type="password" name="password" />
	</p>
	<input type="hidden" name="url" value="<?php echo r::get('url') ?>" />
	<p>
		<input type="submit" name="Anmelden" />
	</p>
</form>