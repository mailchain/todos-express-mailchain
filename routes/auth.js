var express = require("express");
var passport = require("passport");
var MagicLinkStrategy = require("passport-magic-link").Strategy;
var Mailchain = require("@mailchain/sdk").Mailchain;
var db = require("../db");
var router = express.Router();
var mailchain = Mailchain.fromSecretRecoveryPhrase(
  process.env.SECRET_RECOVERY_PHRASE
);
var fromAddress = process.env["FROM_ADDRESS"] || mailchain.user().address;
let createMailchainAddress = function (address) {
  switch (address) {
    case address.match(/^[\d\w\-\_]*@mailchain\.com$/)?.input: // Mailchain address:
      return address;
    case address.match(/^0x[a-fA-F0-9]{40}$/)?.input: // Ethereum address:
      return address + "@ethereum.mailchain.com";
    case address.match(/^.*\.eth$/)?.input: // ENS address:
      return address + "@ens.mailchain.com";
    case address.match(/^.*\.*@mailchain$/)?.input: // Mailchain address without .com:
      return address + ".com";
    default:
      console.error("Invalid address");
  }
};
passport.use(
  new MagicLinkStrategy(
    {
      secret: "keyboard cat", // change this to something secret
      userFields: ["mailchain_address"],
      tokenField: "token",
      verifyUserAfterToken: true,
    },
    async function send(user, token) {
      var link = "http://localhost:3000/login/mailchain/verify?token=" + token;

      var msg = {
        to: [createMailchainAddress(user.mailchain_address)],
        from: fromAddress,
        subject: "Sign in to Todos",
        content: {
          text:
            "Hello! Click the link below to finish signing in to Todos.\r\n\r\n" +
            link,
          html:
            '<h3>Hello!</h3><p>Click the link below to finish signing in to Todos.</p><p><a href="' +
            link +
            '">Sign in</a></p>',
        },
      };
      return await mailchain.sendMail(msg);
    },
    function verify(user) {
      return new Promise(function (resolve, reject) {
        db.get(
          "SELECT * FROM users WHERE mailchain_address = ?",
          [user.mailchain_address],
          function (err, row) {
            if (err) {
              return reject(err);
            }
            if (!row) {
              db.run(
                "INSERT INTO users (mailchain_address, mailchain_address_verified) VALUES (?, ?)",
                [user.mailchain_address, 1],
                function (err) {
                  if (err) {
                    return reject(err);
                  }
                  var id = this.lastID;
                  var obj = {
                    id: id,
                    mailchain_address: user.mailchain_address,
                  };
                  return resolve(obj);
                }
              );
            } else {
              return resolve(row);
            }
          }
        );
      });
    }
  )
);

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        cb(null, { id: user.id, mailchain_address: user.mailchain_address });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});


router.get("/login", function (req, res, next) {
  res.render("login");
});

router.post(
    '/login/mailchain',
    passport.authenticate('magiclink', {
        action: 'requestToken',
        failureRedirect: '/login',
    }),
    function (req, res, next) {
        res.redirect('/login/mailchain/check');
    },
);

router.get('/login/mailchain/check', function (req, res, next) {
    res.render('login/mailchain/check');
});

router.get(
    '/login/mailchain/verify',
    passport.authenticate('magiclink', {
      successReturnToOrRedirect: '/',
      failureRedirect: '/login',
    }),
);

router.post('/logout', function (req, res, next) {
    req.logout(function (err) {
        if (err) {
            return next(err);
        }
        res.redirect('/');
    });
});

module.exports = router;
