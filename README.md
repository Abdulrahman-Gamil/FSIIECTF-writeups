# FSIIECTF-writeups

 ![image](https://github.com/user-attachments/assets/a0ced165-496b-4283-a9e1-353a00106dfa)
 
# Here are four forensic challenges:‎
‎1.‎	Apache Log Analysis

‎2.‎	Authentication Log Investigation

‎3.‎	Intrusion Detection Monitor

‎4.‎	USB Activity Challenge

# Apache Logs:‎ 
 
![image](https://github.com/user-attachments/assets/eb56e92b-c258-49f0-9bce-706b03bb715c)

![image](https://github.com/user-attachments/assets/0f700370-9faf-40a7-85c1-bd702379eed0)

After extracting the .7z file, we examine the format of the extracted file, ‎‎"apache.log," and observe that it is a standard text file.‎

 ![image](https://github.com/user-attachments/assets/67729a3a-cb6e-447c-8d21-9b9dc53d1075)

Upon opening the file, we identify a suspicious log entry containing a lengthy ‎encoded string. To proceed with the analysis, we first need to decode the URL-‎encoded string. Here is the URL from the log: ‎
http://192.168.32.134/mutillidae/index.php?page=user-‎info.php&username=%27+union+all+select+1%2CString.fromCharCode%28%2B70‎‎%2C%2B108%2C%2B97%2C%2B103%2C%2B32%2C%2B10%2C%2B115%2C%‎‎2B32%2C%2B58%2C%2B32%2C%2B70%2C%2B83%2C%2B73%2C%2B73%2C‎‎%2B69%2C%2B67%2C%2B84%2C%2B70%2C%2B123%2C%2B53%2C%2B48%‎‎2C%2B49%2C%2B49%2C%2B57%2C%2B99%2C%2B49%2C%2B56%2C%2B10‎‎0%2C%2B51%2C%2B99%2C%2B52%2C%2B50%2C%2B99%2C%2B56%2C%2B‎‎53%2C%2B98%2C%2B57%2C%2B101%2C%2B102%2C%2B53%2C%2B102%2C‎‎%2B48%2C%2B98%2C%2B49%2C%2B100%2C%2B100%2C%2B98%2C%2B56‎‎%2C%2B101%2C%2B52%2C%2B50%2C%2B125%29%2C3+--‎‎%2B&password=&user-info-php-submit-button=View+Account+Details
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like ‎Gecko) Chrome/92.0.4515.107 Safari/537.36‎
 

![image](https://github.com/user-attachments/assets/796ce4e4-f375-4778-87f1-a3dec1ab13b8)

After pasting the log into the CyberChef online tool and using the URL decode ‎function, we get the following output:‎
String.fromCharCode(+70,+108,+97,+103,+32,+105,+115,+32,+58,+32,+70,+83,+73,‎‎+73,+69,+67,+84,+70,+123,+53,+48,+49,+49,+57,+99,+49,+56,+100,+51,+99,+52,+5‎‎0,+99,+56,+53,+98,+57,+101,+102,+53,+102,+48,+98,+49,+100,+100,+98,+56,+101,‎‎+52,+50,+125)‎
This appears to be a segment of code in a programming language. Since the ‎challenge description indicates that the server uses JavaScript, we should use an ‎online JavaScript compiler to execute this code and interpret the result.‎

 ![image](https://github.com/user-attachments/assets/fe79f2e7-9a8a-4d7b-b66a-198ab862a6b0)

After running the JavaScript code, you successfully retrieved the flag:‎
`FSIIECTF{50119c18d3c42c85b9ef5f0b1ddb8e42}‎`






# Auth log:‎
 
 ![image](https://github.com/user-attachments/assets/a3e1faa9-79c4-4526-92b8-a6eed6cd6253)
 ![image](https://github.com/user-attachments/assets/503978e1-45a6-4bbf-b0b0-f73ddb32d7c0)

After unzipping the .7z file, we determine that the file is a standard text file.‎ 

![image](https://github.com/user-attachments/assets/3f2095b7-06c6-4647-8bb8-8ffc79ea70fc)

Upon opening the file, we observe that the user attempted to brute force the ‎password to gain access. This indicates that the server was targeted with a brute ‎force attack.‎ 
![image](https://github.com/user-attachments/assets/e92c9de1-dfac-4ff0-8d6a-f2ed64c459bc)

In the logs, it is evident that the attacker gained access to the "securitiie" account ‎through a brute force attack. Specifically, at the bottom of the log entry:‎

Aug 17 05:58:49 Ubuntu sudo: securitiie : TTY=pts/2 ; PWD=/home/securitiie ; ‎USER=root ; COMMAND=/usr/sbin/openvpn --dev null --script-security 2 --up ‎‎'/bin/sh -c sh' ‎
The attacker exploited a misconfiguration in sudo to execute privileged commands. ‎They leveraged this misconfiguration to run the openvpn software, which was used ‎to attack the server via the SSH protocol.‎

 ![image](https://github.com/user-attachments/assets/b12b0e43-e5d4-4576-aa59-9c604aaf0798)

Combining all the extracted information and identifying the sub-technique ID ‎T1136.001, we format the flag as follows:‎
`FSIIECTF{bruteforce_ssh_sudo_openvpn_T1136.001}‎`



















# USBchall: ‎
 
![image](https://github.com/user-attachments/assets/24da67e2-37f3-468c-853c-1d0b7374b71c)
![image](https://github.com/user-attachments/assets/2edc6479-e19e-4e87-bff7-a5865f8152c1)

 
After extracting the files from the .7z and then the .zip file, we determine that we are ‎dealing with an image file system.‎
 ![image](https://github.com/user-attachments/assets/37faa8cc-97c6-4311-a54e-dbc4d02eb7cf)

To open the image file system, we will use the FTK Imager tool.‎ 
![image](https://github.com/user-attachments/assets/67799f1b-3e66-46fe-b1fd-9bcb35214f4c)

After reviewing the contents, we notice several interesting files. We will export ‎these files to the host machine for further analysis.‎
![image](https://github.com/user-attachments/assets/4903681f-74ee-49e2-875f-c8e66cdb850c)
![image](https://github.com/user-attachments/assets/7c684254-591b-4a70-a0ce-d23ba8507d5d)

 
 
After examining all the files and finding nothing of interest, we decided to check the ‎metadata of the image. From this, we were able to extract the flag:‎
`FSIIECTF{ff71ec3784ad8e923b0c7ab2044e3bde70a96e472f87a026576482c946dbbb‎53}‎`


 ![image](https://github.com/user-attachments/assets/c3c2c2f2-e63b-45ab-acdb-6d75e1a6e827)

# Here are five OSINT challenges:‎

‎1.‎	Big Lizard 

‎2.‎	Mediterranean Investigation

‎3.‎	Stalk the Date

‎4.‎	Lost Friend

‎5.‎	Search in the Jungle

‎ ‎
# Big lizard : ‎
 
 ![image](https://github.com/user-attachments/assets/14e6955c-f2b9-4b64-8f57-2f26c239f0b5)
 ![image](https://github.com/user-attachments/assets/2b395396-fe33-4daa-adc4-784d54a654c0)


To find the source of the given picture, upload it to Google Lens and perform a ‎search. This will help identify where the image might have appeared online or ‎provide more context about it.‎
 ![image](https://github.com/user-attachments/assets/fc83d26c-acb6-44a9-9d39-de3a354c7fbc)

after clicking the first link, we identify the name of the park from the information ‎provided.‎
 ![image](https://github.com/user-attachments/assets/6fee8525-0de7-44ca-8620-221b7f3f055b)

After decoding the name of the park to MD5, the flag is:‎
`FSIIECTF{bdf2cd24072cddea74f6e04886faf69c}‎`












# Lost friend: ‎
 
![image](https://github.com/user-attachments/assets/c3233032-d330-43db-a25e-95d4fe331600)
![image](https://github.com/user-attachments/assets/c76a8679-df9a-46d5-a0b4-58e8d24b10fe)

 
After using Google Lens and focusing on the shop in the right corner of the image, ‎the search results confirm that the shop's name and appearance match the location in ‎the image.‎
 ![image](https://github.com/user-attachments/assets/e9a72bf2-df81-4f46-882b-fd04e52d0410)


After clicking on the link, we obtain the address of the shop.‎
 ![image](https://github.com/user-attachments/assets/573f1e5e-dd68-4d77-874f-c96187bf3c7f)

Upon visiting the address, we see that the location matches the image.‎
 ![image](https://github.com/user-attachments/assets/cce320a3-684d-40c3-a808-7d76baa84a6e)

From the same link, we extract the flag:‎
`FSIIECTF{13.0585619_80.276355}‎`




















# Mediterranean investigation:‎
 ![image](https://github.com/user-attachments/assets/01cf54f8-e11c-4020-989e-8855b6364009)

For this challenge, we're only provided with a username. Let's begin investigating by ‎searching the username across various platforms and databases to gather more ‎information about the person.‎
 ![image](https://github.com/user-attachments/assets/7e5d97d4-1688-4fb0-b463-370a3fa137bd)

After running the Sherlock tool to search for accounts with the username ‎‎"anonymous57harper," we found that the only relevant result is a GitHub account. ‎Let's visit the GitHub profile to further investigate.‎
 ![image](https://github.com/user-attachments/assets/a6220266-2e1d-4948-a5ec-07ef7000cc6c)

Upon checking the GitHub account, we confirm that the user joined 3 weeks ago, ‎which aligns with the timeline, indicating this is likely the account we are searching ‎for. The account only has one repository, so let's explore it to gather more evidence ‎about the user.‎ 

![image](https://github.com/user-attachments/assets/80a121e1-d8d5-4ff5-bc43-9f7545fd7c4d)


Upon reviewing the commits in the repository, we discovered that the user's full ‎name, "Antoine Fermier," was briefly included in one of the files before being ‎deleted. Now we have successfully identified the full name of the user.‎ 

![image](https://github.com/user-attachments/assets/1f706530-a9f1-48ac-a33f-3cf64c007225)

In the code, we find that the user left his email address as a reminder to feed his dog, ‎‎"Rocky." The email is hackcorp_pentester@gmail.com, which also suggests that the ‎user’s role is a pentester based on the email address.‎

![image](https://github.com/user-attachments/assets/96802c18-e6de-4b93-b477-fdd30f76196f)

 
After searching on X.com (formerly Twitter) using the same GitHub username and ‎finding no results, we tried searching with the user's GitHub name instead. This led ‎us to discover the account belonging to our target.‎
 ‎ 
 ![image](https://github.com/user-attachments/assets/b999b9e0-045f-487f-a157-284662ee3a3f)

By checking the following list on the X.com profile, we found that the user attended ‎Paris-Saclay University.‎

![image](https://github.com/user-attachments/assets/db1c36f1-b95b-41f5-bc24-65e980bdef86)




By examining the user's replies, we can determine that their favorite anime is ‎Jujutsu Kaisen, as they frequently engage with the official account of the anime.‎
 ‎
 ‎ ![image](https://github.com/user-attachments/assets/3d958f4a-126b-4c6f-a900-fdd0a9cfc384)
  ![image](https://github.com/user-attachments/assets/0bb563c3-6e2f-420b-bf40-defd9eab603b)

 ‎ ‎By reviewing his X.com timeline, we come across a post where he shared a recipe in ‎French. From this, we can deduce that his favorite food is likely connected to the ‎recipe he posted.‎

![image](https://github.com/user-attachments/assets/d7ace932-4829-4b22-9fec-9e900edce82f)
![image](https://github.com/user-attachments/assets/d4438fa6-2eca-4c4d-af5d-c3d7ffe8203a)

 ‎ ‎ 
By entering the first few sentences of the recipe into Google, we can locate the exact ‎website where the recipe originated. The dish is called "La bouillabaisse ‎Marseillaise traditionnelle", or "Traditional Marseille Bouillabaisse". From this, we ‎can confirm that the user's favorite dish is Bouillabaisse.‎

 
![image](https://github.com/user-attachments/assets/5b79bd6b-adcd-4e42-8212-349260cc7bba)
![image](https://github.com/user-attachments/assets/aba9a43c-d8fb-49c6-bd55-eade78dae666)

 
Instead of immediately reverse-searching the image to find the location, we noticed ‎a mediatag at the bottom of the post referencing the official Pastebin account. This ‎suggests that the information we are looking for is in a Pastebin, although the link ‎isn't provided directly.‎
Upon re-examining the tweet, the sentence "Just find new routes, Zebras Love Bright ‎Fruits." seems nonsensical with incorrect capitalization. By taking the first letter of ‎each word, we decode the Pastebin URL: https://pastebin.com/JfnrZLBF.‎

 
 ![image](https://github.com/user-attachments/assets/0984eafa-aabb-42ee-94d3-9fc4e6a3bcab)

By searching the text from the Pastebin on Google, we identify it as a poem by John ‎Keats titled "To Fanny."‎




•  Real First Name: Antoine

•  Family Name: Fermier

•  Dog's Name: Rocky

•  Favorite Anime: Jujutsu Kaisen

•  University: University Paris-Saclay

•  Email: hackcorp_pentester@gmail.com

•  Job Position: Pentester

•  Favorite Food: Bouillabaisse

‎  Favorite Woman's Name: Fanny

Combining all the gathered information into the flag format, it would be:‎

`FSIIECTF{antoine_fermier_rocky_jujutsu_kaisen_paris-‎saclay_pentester_bouillabaisse_hackcorp_pentester@gmail.com_fanny}‎`














# Stalk the date ‎
 ![image](https://github.com/user-attachments/assets/848633f6-0057-4e13-92b4-328798910b4a)
‎ ‎
 
The information provided only gives us the username of the target, F14sh_W1l50n. ‎From this username, we need to determine the user's favorite restaurant and dessert. ‎Additionally, we know that the target was the first person to earn the Golden HTML ‎badge in July 2013.‎ 

![image](https://github.com/user-attachments/assets/0db603ba-ba43-433c-9f0f-7f197be94735)

On X.com, we found an account with the same username, F14sh_W1l50n.‎

 ![image](https://github.com/user-attachments/assets/92e87153-754a-4ea2-a2ec-87ad68515964)

We observed a tweet on the targeted account featuring a photo taken at a restaurant. ‎The image reveals the first four letters of the restaurant's name: "Chim".‎

![image](https://github.com/user-attachments/assets/5283341e-3650-4d2d-8056-cab1f7a1fcb5)

 
The next step is to determine the location of the targeted user by examining the ‎Golden HTML badge. We discovered that the platform awarding this badge is Stack ‎Overflow. To proceed, we will investigate Stack Overflow to identify the user who ‎was the first to earn the Golden HTML badge in July 2013.‎
 
 ![image](https://github.com/user-attachments/assets/523a2b2c-55cb-40cf-9c7d-a7459a89e185)
![image](https://github.com/user-attachments/assets/b095f631-c4fc-48ba-8aac-b33d79b6dffd)

https://stackoverflow.com/help/badges/134?page=4‎
 
We located the target user's account and found that their location is England, UK.‎

![image](https://github.com/user-attachments/assets/caa60c12-a7de-40bf-8d4e-fea098f27413)

 
Searching for a steak restaurant in England, UK that starts with "Chim," we find ‎Chimichurris restaurant as a match.‎

 ![image](https://github.com/user-attachments/assets/fe5f255f-f0a2-4d16-8e17-c86df2e7de19)

By examining the reviews of Chimichurris, we notice that the lighting in the ‎restaurant matches the lighting seen in the tweet from the targeted user.‎
 ![image](https://github.com/user-attachments/assets/50238c99-9098-4885-a155-763cb73c3143)

We reviewed the dessert menu at Chimichurris and generated unique MD5 hashes ‎for each dessert option:‎
•	Panqueque with Dulce de Leche: Chimichurris_Panqueques => ‎`FSIIECTF{fa70e925f20f156ec4018f4fecf9bb24}‎`

•	Almond Pudding: Chimichurris_Puddings => ‎`FSIIECTF{8d949fc11c395fead984d46235adea30}‎`

•	Empanada de Manzana: Chimichurris_Empanadas => ‎`FSIIECTF{99dfdd963422ee6b4acd98b5d62a4301}‎`

•	Alfajor Helado: Chimichurris_Alfajores => ‎`FSIIECTF{d797712b3bbefdd084aab2e43f235d36}‎`

•	Ice Cream: Chimichurris_Ice_cream => ‎`FSIIECTF{d5e3707c96d8ac73053b927e8dbb0de0}‎`

To determine the favorite dessert, we match the hash value with the provided hashes ‎and find that the favorite dessert
After testing all five hashes, we found that the correct answer was ‎`FSIIECTF{d797712b3bbefdd084aab2e43f235d36}`, which corresponds to the ‎Alfajores dessert. This confirms that F14sh_W1l50n’s favorite dessert is Alfajores




















