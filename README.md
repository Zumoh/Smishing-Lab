# Smishing-Lab
This repository documents an investigation into a recent smishing (text-based phishing) attempt. It uncovers the tactics and tools used by threat actors to deceive users. Explore a detailed analysis and the key findings.

## Objective

The Detection Lab project aimed to establish a controlled environment for simulating and detecting cyber attacks. The primary focus was to ingest and analyze logs within a Security Information and Event Management (SIEM) system, generating test telemetry to mimic real-world attack scenarios. This hands-on experience was designed to deepen understanding of network security, attack patterns, and defensive strategies.

### Skills Learned

- Threat Identification:
   - Recognizing signs of smishing, such as unsolicited messages, urgency, poor grammar, and suspicious links.
- Analytical Skills:
   - Using tools like VirusTotal, Cisco Talos, AnyRun, WHOIS, and URLscan.io to analyze and interpret data.
   - Understanding and correlating information across multiple cybersecurity tools.
- Dynamic Malware Analysis:
   - Running and observing the behavior of suspicious links and files in a sandbox environment (AnyRun).
   - Interpreting reports on activities, network connections, file modifications, and processes.
- IP Reputation and Domain Analysis:
   - Checking the reputation of IP addresses and domains using services like Cisco Talos and WHOIS.
   - Understanding how domain registration and timing can indicate malicious intent.
- Forensic Reporting:
   - Documenting findings clearly and concisely.
   - Creating detailed reports on analysis and conclusions.
- Preventive Measures:
   - Learning how to identify and avoid potential phishing threats.
   - Advising on actions to take when encountering suspicious messages or links.

### Tools Used

- VirusTotal: To scan link found in the text message.
- Cisco Talos: To evaluate the safety and reputation of IP addresses associated with the url.
- AnyRun: To Execute and analyze the links in a controlled environment to observe its behavior.
- Whois: To acertain ownership details of the domain found in the link.
- URLscan.io: To analyzes the URL to identify its behavior and potential risks.

## Investigation

In the ever-evolving landscape of cybersecurity, threats can come in many forms. Recently, I encountered a smishing text—a text-based phishing attempt designed to deceive users into clicking malicious links. Through a meticulous investigation, I uncovered the deceptive tactics employed by the threat actors and the tools they used to mask their malicious intent. Here’s a detailed account of the analysis and findings.

<img width="611" alt="Screenshot 2025-01-17 at 1 42 29 PM" src="https://github.com/user-attachments/assets/e04a9942-9d4a-460a-bb52-8c520bed1310" />

##

<img width="681" alt="Screenshot 2025-01-17 at 1 40 30 PM" src="https://github.com/user-attachments/assets/f2cf0a9d-351d-4cbd-9899-da2af0e58f2f" />

## Initial Discovery:

The journey began with the receipt of a smishing text on January 4, 2025, containing a suspicious link. Smishing is a type of phishing attack that is carried out through SMS text messages. These texts often aim to trick users into clicking on a link or providing personal information. Recognizing the potential threat, I proceeded to analyze the link to determine its nature and assess its potential impact.

##

<img width="359" alt="Screenshot 2025-01-17 at 1 44 54 PM" src="https://github.com/user-attachments/assets/86b11ba4-c267-4cb0-a28c-64345b25c741" />

## Signs of Smishing

Unsolicited Message(s) From an Unknown Source- This message was unsolicited as I had not ordered anything to be delivered by USPS and I was not expecting a delivery from anyone.
Urgency: The sender created a sense of urgency by suggesting that I click the link within 24 hours.
Poor Grammar and Spelling: The message clearly had grammatical errors, such as using 'can not' instead of 'cannot,' and included wordy phrases like 'due to the detection of an invalid zip code address’.
Suspicious Links: The message included a link that immediately seemed suspicious. Upon further examination, I noticed that the main domain was “-trackwpy.top” while the subdomain was “usps.com.” This inconsistency was alarming because legitimate USPS links should feature “usps.com” as the primary domain. Had I clicked on the link, it would have directed me to a malicious website designed to steal personal information. Such deceptive strategies are typical in phishing schemes, intending to trick users into revealing sensitive information.


## VirusTotal Analysis:

To start my analysis, I submitted the suspicious link to VirusTotal. I entered the link from the text message into VirusTotal to check its safety. This tool combines data from many antivirus programs and website scanners to provide a clear security assessment, helping to detect any malicious activities related to the link.
The results showed that the link was identified as a phishing link by several antivirus engines, indicating that it was designed to deceive users and potentially steal personal information.

##

<img width="625" alt="Screenshot 2025-01-17 at 1 47 21 PM" src="https://github.com/user-attachments/assets/541bc119-391d-4d01-a281-269bbc528671" />

##

VirusTotal provided detailed information about the link, including the IP address it contacts. This information is crucial for further investigation, as it helps in understanding the network infrastructure used by the threat actors.

##

<img width="626" alt="Screenshot 2025-01-17 at 1 48 51 PM" src="https://github.com/user-attachments/assets/d41178cf-594b-4179-a6c5-da756c950b13" />

##

## IP Reputation Check:

While checking the DETAILS tab in VirusTotal, I found an IP address (43[.]153[.]59[.]85) linked to the URL. Using Cisco Talos, I checked the reputation of the IP address identified by VirusTotal. The IP address was found to have a poor reputation, indicating it is associated with malicious activities. This further confirmed that the link was part of a phishing campaign.

##

<img width="622" alt="Screenshot 2025-01-17 at 1 50 16 PM" src="https://github.com/user-attachments/assets/86ed5a23-e9c4-40b3-9dd0-068ac50bf927" />

##

<img width="626" alt="Screenshot 2025-01-17 at 1 52 49 PM" src="https://github.com/user-attachments/assets/109e238c-d14a-4070-a159-db3a5c5d83b6" />

## Dynamic Analysis using AnyRun:

Using AnyRun sandbox, you are safely able to analyze and execute potentially malicious files, URLs or Links in a controlled environment. This allows you to safely execute and analyze potentially harmful content, observe its behavior, and understand its impact without risking your real environment. You can see detailed reports on their activities, including network connections, file modifications, and process creation. This helps in understanding the full impact and potential threats posed by the malicious file.

I used AnyRun to conduct a dynamic analysis of the suspicious link. The service showed that the link attempted to establish a connection with the same IP address identified by VirusTotal. This consistency across tools strengthens the evidence of malicious activity.

##

<img width="626" alt="Screenshot 2025-01-17 at 1 54 47 PM" src="https://github.com/user-attachments/assets/e5d05d67-03f2-4eda-8b57-e345364e1f82" />

##

AnyRun also gives you the ability to interact with files, links, and URLs just as you would on your actual system. You can perform actions such as clicking links, downloading files, and visiting URLs to see how they behave and what processes they trigger.

##

<img width="624" alt="Screenshot 2025-01-17 at 1 56 06 PM" src="https://github.com/user-attachments/assets/f41d9811-11f8-43e0-81b5-e56797136476" />

##

<img width="626" alt="Screenshot 2025-01-17 at 1 56 43 PM" src="https://github.com/user-attachments/assets/c053f739-e1ba-4e21-b4dd-99392e0eed12" />

##

During the analysis, a DNS request was made to the domain "usps.com-trackwpy.top". In this case, "com-trackwpy.top" is the main domain, and "usps.com" is used as a subdomain. This deceptive tactic is often employed to trick users into thinking the link is associated with a legitimate organization (USPS in this case). The subdomain structure was designed to mislead users into believing the link was legitimate, thereby increasing the likelihood of a successful phishing attempt.

##

<img width="624" alt="Screenshot 2025-01-17 at 1 58 05 PM" src="https://github.com/user-attachments/assets/7e54146b-667d-4d71-9d4f-6aaa431468fc" />

##

AnyRun flagged the domain as a suspected phishing domain due to its cross-domain nature, which is a common indicator of phishing attempts.

##

<img width="626" alt="Screenshot 2025-01-17 at 1 59 26 PM" src="https://github.com/user-attachments/assets/1e20e8ca-8f79-4a40-b576-908214498904" />

##

The analysis showed that a process with ID "6676" was created, and it was flagged as 100% malicious. Suricata, an open-source threat detection engine, raised an alert indicating that phishing activity had been detected. This further confirmed the link’s malicious intent.

##

<img width="625" alt="Screenshot 2025-01-17 at 2 02 45 PM" src="https://github.com/user-attachments/assets/9cc536ac-c38e-46c9-aede-9d89a38f6ab6" />

## ANYRUN REPORT

<img width="648" alt="Screenshot 2025-01-17 at 2 04 37 PM" src="https://github.com/user-attachments/assets/3169127f-230d-4dc2-ada2-68ff647e9284" />

##

<img width="673" alt="Screenshot 2025-01-17 at 2 05 40 PM" src="https://github.com/user-attachments/assets/3521b2da-05e9-4724-82fa-90b42ee4c6a7" />

## Domain Lookup:

WHOIS is a tool that allows users to find out who owns domain names and IP addresses. It provides details like registration and expiration dates, contact information, and other technical details. This information is useful for cybersecurity, tracking suspicious domains, and ensuring transparency in domain ownership.

A WHOIS lookup revealed that the domain used in the smishing attempt was registered and created on the same day as the incident. This timing raises suspicion of a hasty setup for malicious purposes. The registrant's name was redacted, making it harder to identify the responsible party.

##

<img width="667" alt="Screenshot 2025-01-17 at 2 06 44 PM" src="https://github.com/user-attachments/assets/b6282b73-a61d-44f8-a5f6-53b7f1b9d758" />

## 

URLscan.io confirmed that the link exhibited malicious activity, consistent with findings from VirusTotal and AnyRun. The service provides a detailed report on the behavior of the URL, including network connections and web content. 

The analysis showed that the link attempted to connect to the same IP address identified by previous tools, reinforcing the conclusion that the link was part of a coordinated phishing campaign.

##

<img width="652" alt="Screenshot 2025-01-17 at 2 08 49 PM" src="https://github.com/user-attachments/assets/386ecd2a-f045-4e59-9378-59dcad9932d6" />

##

The link led to a page crafted to resemble a legitimate USPS page. The purpose of this page was to steal user credentials and potentially download malware or spyware onto the victim’s device. The detailed analysis from URLscan.io provided further evidence of the phishing attempt and the threat actors' tactics.

##

<img width="624" alt="Screenshot 2025-01-17 at 2 09 58 PM" src="https://github.com/user-attachments/assets/36760ae8-c5b3-4c44-bad7-c9da9d86c26a" />

## Conclusion:

The investigation clearly showed that the link in the smishing text was harmful. It used a tricky subdomain setup to make users think it was a real USPS link. Several tools like VirusTotal, Cisco Talos, AnyRun, and URLscan.io confirmed that the link was meant for phishing, which could steal your information and install malware on your device.

## Broader Implications of Smishing Attacks:

Smishing attacks, like the one investigated, are part of a growing trend of cyber threats. They take advantage of how common mobile phones are and how much people trust text messages. These attacks can have serious effects:

- Financial Loss: Victims may give away sensitive financial info, leading to unauthorized transactions.
- Data Breach: Personal and corporate data can be exposed, leading to identity theft.
- Malware Infection: Clicking malicious links can install malware on your device.

## Recommended Actions:

- Think twice before clicking on links, especially those you were not expecting.
- Be cautious and avoid interacting with suspicious messages.
- Always check the sender and message content before clicking links.
- Block any number(s) that engage in such campaigns.
- Report suspicious numbers to your service provider.
- Always verify the authenticity of any message by contacting the company directly through official channels.



## Stay cautious, stay informed, and stay secure!


