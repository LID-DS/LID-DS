import os
import sys
import time
import random
import requests
import argparse
import threading

from pyvirtualdisplay import Display

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.action_chains import ActionChains

MAX_LOGOUT_FAILS = 5
MAX_PRODUCTS = 3


class User:

    def __init__(self,
                 url,
                 email,
                 password,
                 security_question,
                 user_number,
                 chrome_options):
        self.base_url = url
        self.chrome_options = chrome_options
        self.driver = webdriver.Chrome(options=self.chrome_options)
        self.driver.delete_all_cookies()
        self.email = email
        self.password = password
        self.security_question = security_question
        self.user_number = user_number
        self.logout_count = 0
        # to stop thread
        self.is_running = True
        # to see if thread has stopped
        self.is_finished = False
        # relative directory path
        self.dirname = os.path.abspath(os.curdir)
        # feedback xpath changing when next item clicked starts with 3
        self.feedback_path_count = 3

    def reset(self):
        self.__init__(self.base_url,
                      self.email,
                      self.password,
                      self.security_question,
                      self.user_number,
                      self.chrome_options)

    def register(self):

        # Open the website
        self.driver.get(f'{self.base_url}/#/register')
        time.sleep(2)
        try:
            # get rid of pop up window
            self.driver.find_element_by_xpath('/html/body/div[3]/div[2]/div/mat-dialog-container/app-welcome-banner/div/div[2]/button[2]/span[1]/span').click()
        except Exception as e:
            print("User "
                  + str(self.user_number)
                  + ": Error removing welcome banner -> not retrying")
            print(e)
            return False
        try:
            # find email box
            reg_email_box = self.driver.find_element_by_xpath(
                    '//div[contains(@id, "registration-form")]//input[@id="emailControl"]')
            reg_email_box.send_keys(self.email)
            # find password box
            reg_password_box = self.driver.find_element_by_xpath(
                    '//div[contains(@id, "registration-form")]//input[@id="passwordControl"]')
            reg_password_box.send_keys(self.password)
            # find repeat password box
            reg_password_repeat_box = self.driver.find_element_by_xpath(
                    '//div[contains(@id, "registration-form")]//input[@id="repeatPasswordControl"]')
            reg_password_repeat_box.send_keys(self.password)
            # occasional overlapping without sleep
            time.sleep(1)
        except Exception:
            print("User " + str(self.user_number) + ": Error entering email")
            return False
        # select security question
        try:
            self.driver.find_element_by_xpath(
                '/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-register/div/mat-card/div[2]/div[1]/mat-form-field[1]/div/div[1]/div[3]').click()
            self.driver.find_element_by_xpath(
                '//div[contains(@id, "cdk-overlay-2")]//mat-option[@id="mat-option-0"]').click()
        except Exception:
            print("Error selecting security question")
            # rerun registration process
            self.register()
        security_answer_box = self.driver.find_element_by_xpath(
                '//div[contains(@id, "registration-form")]//input[@id="securityAnswerControl"]')
        security_answer_box.send_keys(self.security_question)
        try:
            # click registration button
            self.driver.find_element_by_id('registerButton').click()
        except Exception:
            print("Error clicking register button")
            # rerun registration process
            self.register()
            pass
        return True

    def login(self):
        print("User: " + str(self.user_number) + " " + 'Try logging in')
        # Open the website
        self.driver.get(f'{self.base_url}/#/login')
        try:
            # get rid of pop up window by clicking in top right corner
            self.driver.find_element_by_xpath('//div[contains(@class,"cdk-overlay-pane")]//button[@aria-label="Close Welcome Banner"]').click()
        except Exception:
            print("User: " + str(self.user_number) + " " + 'No Welcome Banner')
            pass
        # Login with given credentials
        try:
            # find email box
            email_box = self.driver.find_element_by_name('email')
            # enter email address
            email_box.send_keys(self.email)
            # find password box
            pass_box = self.driver.find_element_by_name('password')
            # enter password
            pass_box.send_keys(self.password)
            # find login button
            login_button = self.driver.find_element_by_xpath('//div[contains(@id, "login-form")]//button[@id="loginButton"]')
            # click button
            try:
                login_button.click()
            except NoSuchElementException:
                print("User {}: login_button not found".format(self.user_number))
                return False
            time.sleep(1)
            # logout count for too many failed logouts
            self.logout_count = 0
        except NoSuchElementException:
            print("User {}: Login failed".format(self.user_number))
            return False
        # remove cookie overlay window
        try:
            self.driver.find_element_by_xpath('//div[contains(@aria-describedby, "cookieconsent:desc")]//a[@aria-label="dismiss cookie message"]').click()
        except Exception:
            print("User: " + str(self.user_number) + " " + 'No cookie banner')
            pass
        return True

    def logout(self):
        print("User: " + str(self.user_number) + " " + 'Logout')
        self.logout_count += 1
        if (self.logout_count < MAX_LOGOUT_FAILS):
            try:
                account_button = self.driver.find_element_by_xpath(
                    '//*[@id="navbarAccount"]')
                account_button.click()
                logout_button = self.driver.find_element_by_xpath(
                    '//*[@id="navbarLogoutButton"]')
                logout_button.click()
            except Exception:
                print("User: " + str(self.user_number) + " " + "Logout failed, retrying")
                self.reload()
                self.logout()
        else:
            print("User: "
                  + str(self.user_number)
                  + " " + 'max retries for relogin reached \n reinitialize User')
            self.driver.quit()
            self.reset()

    def select_products(self, selected_products, add_to_basket, leave_feedback):

        # product_path = '//div[contains(@class, "ng-star-inserted")]//mat-grid-tile[@style="left: {}; width: calc(33.3333% - 20px); margin-top: {}; padding-top: calc(33.3333% - 20px);"]//button[@aria-label="Add to Basket"]'
        product_button = '/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-search-result/div/div/div[2]/mat-grid-list/div/mat-grid-tile[{}]/figure/mat-card/div[2]/button'
        for selection in selected_products:
            # if last row middle product is chosen
            # wait for popup to close (...put into basket) or else it is obscured
            if selection == 10:
                time.sleep(8)
            else:
                time.sleep(1)
            # select product
            # basket_button = self.driver.find_element_by_xpath(
            # product_path.format(products[selection][0]))#,products[selection][1]))
            # scroll to element so it is clickable
            self.driver.execute_script("arguments[0].scrollIntoView();", product_button)
            if leave_feedback:
                return 0
            if add_to_basket:
                # click Put into Basket
                product_button.click()

    def change_language(self):
        return 0

    def get_product_basket_button(self, product_number):

        # product 7,9,11 have extra banner, so different xpath 
        if product_number in [8, 9, 11]:
            extra_info = 3
        else:
            extra_info = 2
        product_path = f"/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-search-result/div/div/div[2]/mat-grid-list/div/mat-grid-tile[{product_number + 1}]/figure/mat-card/div[{extra_info}]/button"
        basket_button = self.driver.find_element_by_xpath(product_path)
        return basket_button

    def get_product_feedback_field(self, product_number):

        product_path = '/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-search-result/div/div/div[2]/mat-grid-list/div/mat-grid-tile[{}]/figure/mat-card/div[{}]'
        # product 7,9,11 have extra banner -> different xpath
        if product_number in [8, 9, 11]:
            extra_info = 2
        else:
            extra_info = 1
        try:
            product_button = self.driver.find_element_by_xpath(
                product_path.format(product_number + 1, extra_info))
            product_button.click()
        except Exception:
            return None
        try:
            # select feedback window
            # feedback_path = '//*[@id="mat-input-{}"]'
            feedback_path = "//textarea[@aria-label='Text field to review a product']"
            feedback_input = self.driver.find_element_by_xpath(feedback_path)
            self.feedback_path_count += 1
        except Exception:
            print("Error finding feedback field")
            return None
        return feedback_input

    def put_products_in_basket(self, selected_products):

        for selection in selected_products:
            # if last row middle product is chosen
            # wait for popup to close or else it is obscured
            if selection == 10:
                time.sleep(8)
            else:
                time.sleep(1)
            try:
                basket_button = self.get_product_basket_button(selection)
                # scroll to element so it is clickable
                self.driver.execute_script("arguments[0].scrollIntoView();", basket_button)
                basket_button.click()
            except Exception:
                print("User {}: Error putting item {} into basket -> skipping item".format(self.user_number, selection))
                self.logout()
                time.sleep(1)
                self.login()

    def leave_feedback(self, selected_products):

        for selection in selected_products:
            # get feedback field
            feedback_field = self.get_product_feedback_field(selection)
            if feedback_field is None:
                print("User "
                      + str(self.user_number)
                      + ": " + "Error leaving feedback -> skipping feedback")
                return
            # self.driver.execute_script("arguments[0].scrollIntoView();", feedback_field)
            time.sleep(3)
            # enter feedback
            feedback_field.send_keys('u got that juice')
            # get submit button
            submit_path = '//div[contains(@class, "cdk-overlay-pane")]//button[contains(@aria-label, "Send the review")]'
            submit_button = self.driver.find_element_by_xpath(submit_path)
            submit_button.click()
            close_path = '//div[contains(@class, "cdk-overlay-pane")]//button[contains(@aria-label, "Close Dialog")]'
            close_button = self.driver.find_element_by_xpath(close_path)
            close_button.click()

    def complain(self, file_path="/files/test_receipt.zip"):

        print("User " + str(self.user_number) + ": complaining")
        file_path = self.dirname + file_path
        self.driver.get(f'{self.base_url}/#/complain')
        feedback_textarea = self.driver.find_element_by_xpath('//*[@id="complaintMessage"]')
        feedback_textarea.send_keys("I hate your products.")
        time.sleep(2)
        input_file_path = self.driver.find_element_by_xpath('//*[@id="file"]')
        input_file_path.send_keys(file_path)
        time.sleep(2)
        self.driver.find_element_by_xpath(
            '//*[@id="submitButton"]').click()
        time.sleep(2)

    def go_shopping(self, max_products):
        print("User: " + str(self.user_number) + " " + "Go shopping")
        # choose how many items user puts in basket
        how_many_items_in_basket = random.randint(0, max_products)
        random_items = []
        # randomly select what items are chosen
        # with 25% chance leave feedback of chosen product
        try:
            for i in range(0, how_many_items_in_basket + 1):
                random_items.append(random.randint(0, 11))
            for item in random_items:
                # dont continue if user should not run
                if not self.is_running:
                    return
                print("User: " + str(self.user_number) + " " + "Put item into basket")
                self.put_products_in_basket([item])
                if (random.randint(0, 1) > 0):
                    self.reload()
                if (random.randint(0, 4) == 4):
                    print("User {}: Leaving feedback for item {}".format(self.user_number, item))
                    self.leave_feedback([item])
            return True
        except Exception as e:
            print(e)
            return False

    def checkout(self):
        basket_button = self.driver.find_element_by_xpath(
                '/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-navbar/mat-toolbar/mat-toolbar-row/button[4]')
        basket_button.click()
        try:
            # TODO test not working
            # wait for basket to load
            time.sleep(5)
            checkout_button = self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-basket/mat-card/button')
            checkout_button.click()
        except NoSuchElementException:
            print("User " + str(self.user_number) + ": has nothing in cart to checkout")
            return False
        # check if address has to be added -> check if radiobutton for address exists
        try:
            time.sleep(2)
            self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-address-select/div/app-address/mat-card/mat-table/mat-row/mat-cell[1]/mat-radio-button').click()
            address_radio_button = self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-address-select/div/app-address/mat-card/mat-table/mat-row/mat-cell[1]/mat-radio-button')
            address_radio_button.click()
            time.sleep(2)
            # continue with chosen address
            continue_button = self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-address-select/div/app-address/mat-card/button')
            continue_button.click()
        except NoSuchElementException:
            print("User " + str(self.user_number) + ": No address set")
            try:
                time.sleep(2)
                self.driver.find_element_by_xpath(
                        '/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-address-select/div/app-address/mat-card/div/button').click()
                time.sleep(0.2)
                self.driver.find_element_by_xpath(
                        '/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-address-create/div/mat-card/div[1]/mat-form-field[1]/div/div[1]/div[3]/input').send_keys("Land")
                time.sleep(0.2)
                self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-address-create/div/mat-card/div[1]/mat-form-field[2]/div/div[1]/div[3]/input').send_keys("Name")
                time.sleep(0.2)
                self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-address-create/div/mat-card/div[1]/mat-form-field[3]/div/div[1]/div[3]/input').send_keys("1234567")
                time.sleep(0.2)
                self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-address-create/div/mat-card/div[1]/mat-form-field[4]/div/div[1]/div[3]/input').send_keys("72072")
                time.sleep(0.2)
                self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-address-create/div/mat-card/div[1]/mat-form-field[5]/div/div[1]/div[3]/textarea').send_keys("Street")
                time.sleep(0.2)
                self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-address-create/div/mat-card/div[1]/mat-form-field[6]/div/div[1]/div[3]/input').send_keys("Stadt")
                time.sleep(0.2)
                self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-address-create/div/mat-card/div[1]/mat-form-field[7]/div/div[1]/div[3]/input').send_keys("Bundesland")
                time.sleep(0.2)
                self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-address-create/div/mat-card/div[2]/button[2]').click()
                time.sleep(2)
                # select address
                self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-address-select/div/app-address/mat-card/mat-table/mat-row/mat-cell[1]/mat-radio-button').click()
                time.sleep(2)
                # continue with chosen address
                continue_button = self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-address-select/div/app-address/mat-card/button')
                continue_button.click()
            except NoSuchElementException:
                print("User " + str(self.user_number) + ": Error adding address")
                return False
        try:
            time.sleep(2)
            # choose delivery method
            self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-delivery-method/mat-card/div[3]/mat-table/mat-row[3]/mat-cell[1]/mat-radio-button').click()
            # confirm delivery method
            self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-delivery-method/mat-card/div[4]/button[2]/span').click()
        except NoSuchElementException:
            print("User " + str(self.user_number) + ": Error chosing delivery method")
            return False
        try:
            # check if credit card information was added previously
            self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-payment/mat-card/div/app-payment-method/div/div[1]/mat-table/mat-row/mat-cell[1]/mat-radio-button')
        except NoSuchElementException:
            try:
                print("User " + str(self.user_number) + ": Add new card information")
                time.sleep(1)
                # add credit card information
                self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-payment/mat-card/div/app-payment-method/div/div/mat-expansion-panel/mat-expansion-panel-header').click()
                time.sleep(1)
                self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-payment/mat-card/div/app-payment-method/div/div/mat-expansion-panel/div/div/div/mat-form-field[1]/div/div[1]/div[3]/input').send_keys('Name')
                time.sleep(1)
                self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-payment/mat-card/div/app-payment-method/div/div/mat-expansion-panel/div/div/div/mat-form-field[2]/div/div[1]/div[3]/input').send_keys('1234567891011121')
                time.sleep(1)
                month_option = self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-payment/mat-card/div/app-payment-method/div/div/mat-expansion-panel/div/div/div/mat-form-field[3]/div/div[1]/div[3]/select/option').click()
                time.sleep(1)
                self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-payment/mat-card/div/app-payment-method/div/div/mat-expansion-panel/div/div/div/mat-form-field[4]/div/div[1]/div[3]/select/option[1]').click()
                time.sleep(1)
                self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-payment/mat-card/div/app-payment-method/div/div/mat-expansion-panel/div/div/button').click()
                time.sleep(1)
            except NoSuchElementException:
                print("User " + str(self.user_number) + ": Error choosing credit card information")
                return False
            try:
                time.sleep(1)
                # choose added credit card
                self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-payment/mat-card/div/app-payment-method/div/div[1]/mat-table/mat-row/mat-cell[1]/mat-radio-button').click()
                time.sleep(1)
            except NoSuchElementException:
                print("User " + str(self.user_number) + ": Error choosing credit card information")
                return False
        try:
            # continue
            self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-payment/mat-card/div/div[2]/button[2]').click()
            time.sleep(2)
            # checkout
            self.driver.find_element_by_xpath('/html/body/app-root/div/mat-sidenav-container/mat-sidenav-content/app-order-summary/mat-card/div[2]/mat-card/button').click()
            time.sleep(2)
        except NoSuchElementException:
            print("User " + str(self.user_number) + ": error finishing checkout")
        return True

    def reload(self):
        self.driver.refresh()

    def action(self):
        """
        register and loop
        --> login user
        --> go shopping(includes leaving feedback)
        --> complain with uploading zip
        --> logout
        """
        # -->
        print(f"Start behaviour of user {self.user_number}")
        try:
            sys.stdin.readline()
            if not self.register():
                print("error creating user -> skipping")
                return
            time.sleep(0.1)
            while True:
                print(f"User {self.user_number}: Done register user")
                sys.stdin.readline()
                if not self.login():
                    return
                print(f"User {self.user_number}: Done log in")
                # -->
                # includes leaving feedback
                sys.stdin.readline()
                smh_in_cart = self.go_shopping(MAX_PRODUCTS)
                if smh_in_cart:
                    print(f"User {self.user_number}: Done shopping")
                # -->
                # leave complaint
                sys.stdin.readline()
                self.complain()
                print(f"User {self.user_number}:Done complaining")
                # -->
                # checkout cart if it was filled in go_shopping()
                sys.stdin.readline()
                if smh_in_cart:
                    if self.checkout():
                        print(f"User {self.user_number}: Paid for products")
                # logout after shopping
                sys.stdin.readline()
                self.logout()
        except Exception as e:
            print(e)
            self.driver.quit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='HTTPS-Client Simulation.')

    parser.add_argument('-ip',
                        dest='server_ip',
                        action='store',
                        type=str, required=True,
                        help='The IP address of the target server')
    parser.add_argument('-v',
                        dest='verbose',
                        action='store',
                        type=bool,
                        required=False,
                        default=False,
                        help='Make the operations more talkative')

    args = parser.parse_args()

    # Disable requests warnings (caused by self signed server certificate)
    requests.packages.urllib3.disable_warnings()

    # Virtual display to run chrome-browser
    display = Display(visible=0, size=(1920, 1080))
    display.start()

    # Headless chrome-browser settings
    chrome_options = Options()
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument('--ignore-certificate-errors')
    chrome_options.add_argument('--disable-dev-shm-usage')
    chrome_browser = webdriver.Chrome(options=chrome_options)

    url = "http://" + args.server_ip + ':3000'

    password = "testpassword"
    security_question = "middlename"
    user_number = random.randint(0, 10000)
    email = f"mail{user_number}@test.com"
    print("Creating User")
    user = User(url,
                email,
                password,
                security_question,
                user_number,
                chrome_options)
    possible_actions = [
        "shop",
        "complain",
        "checkout"
    ]
    first_call = True
    was_shopping = False
    user.action()
