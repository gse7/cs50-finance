import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import create_engine
import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    user_shares = db.execute("SELECT SUM(shares) as shares FROM transactions WHERE user_id=?", user_id)
    print(user_shares)

    if user_shares[0]["shares"] == None:
        return apology("please buy some stocks, XX", 999)
    #find symbol in db

    #transactions_db = db.execute("SELECT * FROM transactions WHERE user_id=?", user_id)

    transactions = db.execute("SELECT symbol, name, SUM(shares) AS shares, price, SUM(total) AS total FROM transactions WHERE user_id =? GROUP BY symbol", user_id)
    print(transactions)
    #cash
    cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    cash = cash_db[0]["cash"]
    total_sum = transactions[0]["shares"]
    total = total_sum + cash
    #total

    #all shares value


    return render_template("index.html", transactions=transactions, cash=cash, total=total )







@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]

    #get symbol from user
    symbol = request.form.get("symbol")

    #GET
    if request.method == "GET":
        #get all symbols that user have in portfolio
        symbols_user = db.execute("SELECT symbol FROM transactions WHERE user_id=? GROUP BY symbol" , user_id)
        return render_template("sell.html", symbols = [row["symbol"] for row in symbols_user])

    else:
        #get value from shares field to minus stocks out of portfolio
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        stock = lookup(symbol.upper())
        if stock == None:
            return apology("symbol does not exist")

        if shares < 0:
            return apology("Share not allowed")

        transaction_value = shares * stock["price"]

        user_cash_db = db.execute("SELECT cash FROM users WHERE id=?", user_id)
        user_cash = user_cash_db[0]["cash"]

        user_shares = db.execute("SELECT SUM(shares) AS shares FROM transactions WHERE user_id=? AND symbol = ? GROUP BY symbol", user_id, symbol)
        user_shares_real = user_shares[0]["shares"]

        if shares > user_shares_real:
            return apology("not enought shares")

        updt_cash = user_cash + transaction_value

        db.execute("UPDATE users SET cash = ? WHERE id = ?", updt_cash, user_id)

        date = datetime.datetime.now()

       # db.execute("SELECT shares FROM transactions WHERE user_id=? AND (shares - ?) = shares", user_id, shares_value)
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date, name, total) VALUES(?, ?, ?, ?, ?, ?, ?)",session["user_id"], stock['symbol'], shares*(-1), stock['price'], date, stock['name'], (shares*stock['price']))

        flash("Sold!")

        #show table on index
        return redirect("/")




@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = user_id = session["user_id"]
    transactions_db = db.execute("SELECT * FROM transactions WHERE user_id=?", user_id)



    return render_template("history.html", transactions = transactions_db)



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    #check user inputs

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # Ensure username was submitted
        #checkUsername = db.execute("SELECT username FROM users WHERE username=?",
        if not request.form.get("username") or request.form.get("username") == "":
            return apology("Please, provide username", 403)

        # Query database for username
        users = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(users) > 0:
            return apology("Username already exists", 403)

        # Ensure password was submitted
        elif not request.form.get("password") or request.form.get("username") == "":
            return apology("Please, provide password", 403)

        elif request.form.get("confirmation") == "":
            return apology("Please, provide confirmation", 403)


        elif request.form.get("confirmation") != request.form.get("password"):
            return apology("Password and confirmation not same", 403)


        # convert password with hash function
        #username = request.form.get("username")
        #password = request.form.get("password")
        hashed_password = generate_password_hash(password, method='pbkdf2:sha1', salt_length=8)



        # add info into db
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hashed_password)


        # Ensure username exists and password is correct
        #if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
        #   return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        # session["user_id"] = rows[0]["id"]
        flash("Registered")
        # Redirect user to home page
        return redirect("/")


    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")





@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    # find quote in all off the quotes
    if request.method == "GET":
        return render_template("quote.html")

    elif request.method == "POST":
        symbol = request.form.get("quote")
        quote = lookup(symbol)

    #return render_template("quoted.html", name=name)
    #add lookup into sentence


    return render_template("quoted.html", quote=quote)



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    user_cash = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])


    if request.method == "GET":
        return render_template("buy.html")

    #post
    else:
        #check what user want to buy
        symbol = request.form.get("symbol")
        #check how many shares user want yo buy
        shares = int(request.form.get("shares"))

        if not symbol:
            return apology("Please give Symbol")

        quotes = lookup(symbol.upper())

        if quotes == None:
            return apology("Quote Does Not Exist")

        #define user cash
        user_cash_db = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])
        user_cash = user_cash_db[0]["cash"]
        #define transaction value
        transaction_value = shares * quotes["price"]

        #check that user have enough cash to proceed order
        if user_cash < transaction_value:
            return apology("not enough cash")

        #update user cash
        updt_cash = user_cash - transaction_value

        #update value in db
        db.execute("UPDATE users SET cash = ? WHERE id =?", updt_cash, session["user_id"])

        date = datetime.datetime.now()

        #if user have noo
        #find items in there and put it in table
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date, name, total) VALUES(?, ?, ?, ?, ?, ?, ?)",session["user_id"], quotes['symbol'], shares, quotes['price'], date, quotes['name'], (shares*quotes['price']))
        flash("Bought!")
        #insert quotes into table with shared quotes

        #show table on index
        return redirect("/")






