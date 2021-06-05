###WalkThrough for Vulnhub machine SecureCode1
<https://www.vulnhub.com/entry/securecode-1,651/>

###Vulnerable Machine Author: sud0root

###WalkThrough by ApexPredator

 

SPOLIERS BELOW only use if stuck, except take this first time saving
hint to get the source code

Enumerate webroot for zip files to get the source code

![](media/image1.png){width="6.5in" height="4.440972222222222in"}

 

![](media/image2.png){width="6.5in" height="4.673611111111111in"}

 

Download source_code.zip to begin analyzing the source code

![](media/image3.png){width="6.5in" height="4.304861111111111in"}

 

There is a password reset option that uses an insecure random number
generator to create tokens, however it\'s not so simple to crack and
guess the token so likely rabbithole

![](media/image4.png){width="6.5in" height="2.084722222222222in"}

Pages that require authentication have include
../include/isAuthenticated.php at the top

![](media/image5.png){width="6.5in" height="1.9708333333333334in"}

It checks to see if id_level is set for the session (1 for admin, 2 for
customer)

![](media/image6.png){width="6.5in" height="1.4930555555555556in"}

 

![](media/image7.png){width="6.5in" height="3.234722222222222in"}

Source_code.zip also contains the initial database showing users admin
and customer and there id_levels

![](media/image8.png){width="6.5in" height="2.4680555555555554in"}

The password reset page will set the token field for the user\'s entry
in the user database table

![](media/image9.png){width="6.5in" height="3.0569444444444445in"}

Viewitem.php does not have the include/isAuthenticated.php and does a
manual check but does not break out from the code if id_level is not set
and client doesn\'t redirect allowing access to the SQL query where \$id
is not surround with single quotes making it injectable

![](media/image10.png){width="6.5in" height="3.901388888888889in"}

Manually verify that admin is a valid account by requesting a token

![](media/image11.png){width="6.5in" height="3.7979166666666666in"}

Admin is valid

![](media/image12.png){width="6.5in" height="5.061805555555556in"}

Attempting to manually navigate to item/viewitem.php in the browser
redirects to login as expected, if an id is passed a valid id (1) goes
to black page and invalid (0) redirects to login page

![](media/image13.png){width="6.5in" height="2.3868055555555556in"}

Valid and unvalid item ids determined by the list of item images under
item/image

![](media/image14.png){width="2.9166666666666665in" height="2.5in"}

When the request is viewed in burp you can see a valid id returns HTTP
status 404 (as mentioned in the code) and invlaid redirects to login
page

![](media/image15.png){width="6.5in" height="4.661111111111111in"}

 

![](media/image16.png){width="6.5in" height="3.7493055555555554in"}

Test SQL injection with id=1 AND 1=1 (use + instead of spaces)

![](media/image17.png){width="6.5in" height="3.9965277777777777in"}

404 returned as expected test 1=2 to verify false redirects

![](media/image18.png){width="6.5in" height="4.439583333333333in"}

Build boolean based SQL query to determine token, start by verifying we
can pull the admin user account name where we know the first letter is a
with
id=1+AND+ascii(substring((select+username+from+user+WHERE+id_level+=1+LIMIT+1),1,1))+=97
\*\*97 is the ASCII code for a

![](media/image19.png){width="6.5in" height="4.14375in"}

Verify false for wrong first letter (b)

![](media/image20.png){width="6.5in" height="3.8722222222222222in"}

Verify second letter is d

![](media/image21.png){width="6.5in" height="3.99375in"}

Now change query to select token instead of username and build loop to
expose token. PoC.py contains the necessary code. Request token for
admin account, pull token thru SQLi, reset password and login. Flag1
will be visible after login

![](media/image22.png){width="6.5in" height="3.348611111111111in"}

Reviewing the items pages shows that newitem.php contains blacklisted
file extensions and checks mime type for image upload for new item

![](media/image23.png){width="6.5in" height="2.4291666666666667in"}

Updateitem only has a file extension blacklist

![](media/image24.png){width="6.5in" height="2.2472222222222222in"}

.phar is not excluded and is executed as php, similar to a java jar file
but for php

![](media/image24.png){width="6.5in" height="2.2472222222222222in"}

Construct a simple phar to exec a reverse shell

![](media/image25.png){width="6.5in" height="1.2993055555555555in"}

Build final PoC script to put all the pieces together

![](media/image26.png){width="6.5in" height="1.7222222222222223in"}

 

![](media/image27.png){width="6.5in" height="4.807638888888889in"}

 
