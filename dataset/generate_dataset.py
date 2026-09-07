import os
import csv
import random

def generate_spam_dataset(output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # 1. Email Ham Templates (Professional & Personal)
    email_ham_templates = [
        "Hi {}, can we reschedule our meeting to tomorrow at {} PM? Thanks.",
        "Please find attached the project status report for Q{} review. Let me know your thoughts.",
        "Hey team, the sprint planning session is confirmed for {} at 10:00 AM.",
        "Thank you for your order #{}. Your package has been dispatched and will arrive by {}.",
        "Dear {}, your monthly bank statement for account ending in {} is ready for viewing in your portal.",
        "Reminder: The weekly engineering standup will start in 15 minutes on Google Meet.",
        "Hi {}, could you review the pull request for the authentication module when you have a moment?",
        "Your flight booking reference {} from Mumbai to Delhi is confirmed for departure at {}.",
        "Please submit your semester assignment before Friday 5:00 PM on the university portal.",
        "Here are the notes and action items from yesterday's discussion with the client.",
        "Good morning, here is the updated presentation deck for our team demonstration.",
        "Hi {}, let's catch up for lunch today around 1:00 PM if you're free.",
        "Your appointment with Dr. Sharma has been booked for tomorrow at 4:30 PM.",
        "Receipt for your recent payment of Rs. {} to Electric Utility Services.",
        "Hi all, please note the office will remain closed on Monday on account of public holiday.",
        "Here is the shared project document: https://docs.google.com/document/d/proj{} - please review.",
        "Check this GitHub repository for the code implementation: https://github.com/team-dev/repo{}"
    ]

    # 2. SMS Ham Templates (Official Transactional Notifications)
    sms_transactional_ham = [
        "Your OTP for online transaction of Rs. {} at Amazon is {}. Valid for 10 mins. Do not share OTP with anyone. - HDFC Bank",
        "Dear Customer, your A/C ending {} is credited with Rs. {} on {}. Avail Bal: Rs. {}. - SBI",
        "Your package with tracking #{} will be delivered today by courier. Contact delivery associate at +91 98{} to coordinate.",
        "Reminder: Your doctor appointment is scheduled for tomorrow at {} PM at City Clinic.",
        "Your cab driver {} (+91 97{}) has arrived at your pickup location. PIN is {}.",
        "Your monthly mobile postpaid bill of Rs. {} is due on {}. Pay via Airtel Thanks App to avoid late charges.",
        "Your order from Zomato is on its way. Delivery partner is moving towards your location.",
        "Dear customer, cash withdrawal of Rs. {} from ATM at {} was successful. - ICICI Bank"
    ]

    # 3. Personal & Friend Casual Chat Templates (Conversational Peer-to-Peer Ham)
    sms_personal_ham = [
        "Hey bro, call me urgently at +91-{} when you are free, need your help.",
        "Call me urgently, it is important.",
        "Bhai, call me at +91-{} as soon as possible.",
        "Please call me at +91-{} immediately, need some help.",
        "Please pick up the phone, need to ask you something urgent.",
        "Hey {}, can you send me Rs. {} on GPay? Will return it tomorrow.",
        "Can you transfer money for movie tickets? My UPI is not working.",
        "Sent you Rs. {} on PhonePe for yesterday's dinner bill.",
        "Split the cab fare on UPI, your share is Rs. {}.",
        "Can you pay Rs. {} for the pizza? I will give you cash tonight.",
        "Are you free tonight? Let's go to that cafe.",
        "Bhai where are you? Waiting outside the metro station.",
        "Mom said dinner is ready, come home soon.",
        "I lost my phone, this is my new temporary number +91-{}, save it.",
        "Hey dad, reached the station safely, booking cab now.",
        "Happy birthday bro! Have an awesome year ahead!",
        "Congratulations on getting the job offer, so proud of you!",
        "Check this out: https://youtube.com/watch?v={}",
        "Watch this funny clip: https://youtu.be/{}",
        "Read this article when free: https://wikipedia.org/wiki/Topic{}",
        "Can you share the assignment PDF with me?",
        "Hey are you coming to class today? Professor is taking attendance.",
        "Can you send the lecture notes from yesterday?",
        "Let's meet at the library around {} PM to finish the group project.",
        "Thanks for your help with the bug in the code earlier.",
        "Sorry for the late reply bro, was stuck in heavy traffic.",
        "Hey {}, I have reached the restaurant. Let me know when you arrive.",
        "Bro, did you complete the homework for tomorrow's class?",
        "Are you awake? Give me a quick ring when you see this.",
        "Can you share {}'s contact number with me?",
        "Hey dude, what time does the match start today?"
    ]

    # 4. Email Spam Templates (Cyber Threats, Phishing, Malware)
    email_spam_templates = [
        "URGENT: Your bank account has been temporarily locked due to suspicious activity. Verify immediately: https://secure-bank-verify{}.com/login",
        "Congratulations! You have won Rs. {} in the international lottery. Claim your reward now: http://claim-prize{}.xyz/bonus",
        "Security Alert! Unauthorized login attempt detected from IP {}. Confirm your password here: http://{}/account/update",
        "Your pending invoice #{}.pdf is ready for download. Click here: https://billing-doc{}.com/invoice.exe",
        "FINAL WARNING: Your email account will be permanently deactivated within 24 hours. Click to reactivate: https://mail-security-desk{}.net/verify",
        "Earn $5000 weekly working from home with no experience needed! Sign up today: http://quick-cash-scheme{}.biz/register",
        "Dear Customer, you received a tax refund of Rs. {}. Submit your bank credentials to deposit: https://incometax-refund-portal{}.org/claim",
        "You have 1 new unread secure message from Payroll Department. Access document: https://payroll-update{}.com/login.php",
        "Exclusive Offer: 90% discount on luxury watches and electronics. Limited stock available: http://discount-store{}.xyz/shop",
        "Crypto Alert: Deposit 0.1 BTC and receive 1.0 BTC within 24 hours guaranteed! Join: http://crypto-doubler{}.top/invest"
    ]

    # 5. SMS Spam Templates (Smishing, Fake Officials, Advance-Fee Scams)
    sms_spam_templates = [
        "Dear consumer, your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please call our electricity officer at +91-{} immediately.",
        "Dear SBI user, your YONO account has been blocked due to unverified PAN card. Please update immediately: http://bit.ly/sbi-yono-update{} or call +91-{}.",
        "Part-time job offer: Earn Rs. 2000 to Rs. 6000 daily from home by simply liking YouTube videos! Contact on WhatsApp +1 (555) 349-{} now.",
        "Congratulations! Your mobile number has won Rs. 25,00,000 in KBC All India Lucky Draw. Call executive at +91-{} to claim your prize cheque.",
        "URGENT: Your SIM card KYC is incomplete. Your outgoing calls will be stopped in 24 hrs. Call customer care helpline at 1800-{} or +91-{} immediately.",
        "Credit card limit increased to Rs. 5,00,000 without income proof! Claim your pre-approved card now: http://card-upgrade{}.xyz or WhatsApp +91-{}.",
        "Your parcel delivery has failed due to missing street address. Update your address within 12 hours: http://courier-address-fix{}.top or call driver +91-{}.",
        "Dear customer, your loan of Rs. 3,50,000 is approved at 2% interest rate. No CIBIL score required. Call loan officer at +91-{} to disburse funds."
    ]

    names = ["Soham", "Rahul", "Priya", "Amit", "Ananya", "Rohan", "Sneha", "Vikram", "Kavita", "Aditya", "Sameer", "Tanvi"]
    days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    ips = ["192.168.1.105", "45.33.32.156", "185.220.101.5", "103.251.167.20", "194.165.16.88"]

    records = []

    # 1,800 HAM records total:
    # - 600 Email Ham
    # - 500 Transactional SMS Ham
    # - 700 Personal/Conversational Friend Chat Ham
    for _ in range(600):
        t = random.choice(email_ham_templates)
        msg = t.format(random.choice(names), random.randint(1, 12), random.randint(1, 4), random.randint(10000, 99999), random.choice(days), random.randint(1000, 9999), random.randint(500, 8000))
        records.append(('ham', msg))

    for _ in range(500):
        t = random.choice(sms_transactional_ham)
        msg = t.format(random.randint(200, 15000), random.randint(100000, 999999), random.randint(1000, 9999), random.randint(5000, 80000), random.choice(days), random.randint(10000, 99999), random.randint(10000000, 99999999))
        records.append(('ham', msg))

    for _ in range(700):
        t = random.choice(sms_personal_ham)
        phone = random.randint(7000000000, 9999999999)
        amount = random.randint(50, 2000)
        code = random.randint(10000, 99999)
        hour = random.randint(1, 9)
        name = random.choice(names)
        msg = t.format(name if '{}' in t else phone, phone, amount, code, hour)
        records.append(('ham', msg))

    # 1,800 SPAM records total:
    # - 900 Email Phishing / Scam
    # - 900 SMS Smishing / Vishing / Scam
    for _ in range(900):
        t = random.choice(email_spam_templates)
        msg = t.format(random.randint(10, 999), random.randint(100000, 9900000), random.choice(ips), random.choice(ips))
        records.append(('spam', msg))

    for _ in range(900):
        t = random.choice(sms_spam_templates)
        msg = t.format(random.randint(7000000000, 9999999999), random.randint(100, 999), random.randint(7000000000, 9999999999), random.randint(1000, 9999))
        records.append(('spam', msg))

    random.seed(42)
    random.shuffle(records)

    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['label', 'message'])
        writer.writerows(records)

    print(f"Generated {len(records)} balanced records (Email + Transactional SMS + Personal Friend Chat Ham vs Cyber Threats) in {output_path}")

if __name__ == '__main__':
    dataset_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'spam.csv')
    generate_spam_dataset(dataset_file)
