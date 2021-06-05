###WalkThrough for Vulnhub machine SecureCode1
<https://www.vulnhub.com/entry/securecode-1,651/>

###Vulnerable Machine Author: sud0root

###WalkThrough by ApexPredator

 

SPOLIERS BELOW only use if stuck, except take this first time saving
hint to get the source code

Enumerate webroot for zip files to get the source code

![](ScreenShots/image1.png)

 

![](ScreenShots/image2.png)

 

Download source_code.zip to begin analyzing the source code

![](ScreenShots/image3.png)

 

There is a password reset option that uses an insecure random number
generator to create tokens, however it\'s not so simple to crack and
guess the token so likely rabbithole

![](ScreenShots/image4.png)

Pages that require authentication have include
../include/isAuthenticated.php at the top

![](ScreenShots/image5.png)

It checks to see if id_level is set for the session (1 for admin, 2 for
customer)

![](ScreenShots/image6.png)

 

![](ScreenShots/image7.png)

Source_code.zip also contains the initial database showing users admin
and customer and there id_levels

![](ScreenShots/image8.png)

The password reset page will set the token field for the user\'s entry
in the user database table

![](ScreenShots/image9.png)
Viewitem.php does not have the include/isAuthenticated.php and does a
manual check but does not break out from the code if id_level is not set
and if the client doesn\'t redirect it allows access to the SQL query where \$id
is not surround with single quotes making it injectable

![](ScreenShots/image10.png)

Manually verify that admin is a valid account by requesting a token

![](ScreenShots/image11.png)

Admin is valid

![](ScreenShots/image12.png)

Attempting to manually navigate to item/viewitem.php in the browser
redirects to login as expected, if an id is passed a valid id (1) goes
to blank page and invalid (0) redirects to login page

![](ScreenShots/image13.png)
Valid and unvalid item ids determined by the list of item images under
item/image

![](ScreenShots/image14.png)

When the request is viewed in burp you can see a valid id returns HTTP
status 404 (as mentioned in the code) and invlaid redirects to login
page

![](ScreenShots/image15.png)
 

![](ScreenShots/image16.png)

Test SQL injection with id=1 AND 1=1 (use + instead of spaces)

![](ScreenShots/image17.png)

404 returned as expected test 1=2 to verify false redirects with status code 302

![](ScreenShots/image18.png)

Build boolean based SQL query to determine token, start by verifying we
can pull the admin user account name where we know the first letter is a
with
id=1+AND+ascii(substring((select+username+from+user+WHERE+id_level+=1+LIMIT+1),1,1))+=97
\*\*97 is the ASCII code for a

![](ScreenShots/image19.png)
Verify false for wrong first letter (b)

![](ScreenShots/image20.png)
Verify second letter is d

![](ScreenShots/image21.png)

Now change query to select token instead of username and build loop to
expose token. PoC.py contains the necessary code. Request token for
admin account, pull token thru SQLi, reset password and login. Flag1
will be visible after login

![](ScreenShots/image22.png)
Reviewing the items pages shows that newitem.php contains blacklisted
file extensions and checks mime type for image upload for new item

![](ScreenShots/image23.png)

Updateitem only has a file extension blacklist

![](ScreenShots/image24.png)

.phar is not excluded and is executed as php, similar to a java jar file
but for php

![](ScreenShots/image24.png)

Construct a simple phar to exec a reverse shell

![](ScreenShots/image25.png)

Build final PoC script to put all the pieces together

![](ScreenShots/image26.png)

 

![](ScreenShots/image27.png)

 
