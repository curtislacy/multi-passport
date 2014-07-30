/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util')
  , lookup = require('./utils').lookup
  , _ = require( 'lodash' );


/**
 * `Strategy` constructor.
 *
 * The local authentication strategy authenticates requests based on the
 * credentials submitted through an HTML-based login form.
 *
 * Applications must supply a `verify` callback which accepts `username` and
 * `password` credentials, and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `usernameField`  field name where the username is found, defaults to _username_
 *   - `passwordField`  field name where the password is found, defaults to _password_
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new LocalStrategy(
 *       function(username, password, done) {
 *         User.findOne({ username: username, password: password }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = {};
  }
  if (!verify) { throw new TypeError('MultiPassport Strategy requires a verify callback'); }
  if( !options.passport ) { throw new TypeError( 'MultiPassport Strategy requires a "passport" option.' ); }
    
  passport.Strategy.call(this);
  this.strategies = {};
  this.passport = options.passport;
  this.name = 'local';
  this._verify = verify;
  this._passReqToCallback = options.passReqToCallback;

  var self = this;
  function timeout() {
    var curTime = new Date().getTime();
    var ball = [];
    _.reduce( Object.keys( self.passport._strategies ), function( ball, flake ) {
      var remoteStrategy = self.passport._strategy( flake );
      return ( remoteStrategy.lastUsed && (( curTime - remoteStrategy.lastUsed ) > 6000000 )) ? ball.push( flake ) : ball;
    }, ball )

    ball.forEach( function( keyToRemove ) {
      self.passport.unuse( keyToRemove );
      delete self.strategies[ keyToRemove ];
    });
    setTimeout( timeout, 60000 );
  }
  setTimeout( timeout, 60000 );

}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

Strategy.prototype.register = function( key, strategy, extendOptions, handler ) {
  this.strategies[ key ] = {
    strat: strategy,
    extendOptions: extendOptions,
    handler: handler
  }
}

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {

  var stratKey = options.clientApp + ':' + options.type;
  var remoteStrategy = req.app.passport._strategy( stratKey );
  if( !remoteStrategy)
  {
    remoteStrategy = new ( this.strategies[ options.type ].strat )
                            ( this.strategies[ options.type ].extendOptions( options.connectionData ), 
                              new this.strategies[ options.type ].handler );
    this.passport.use( stratKey, remoteStrategy );
  }
  remoteStrategy.lastUsed = new Date().getTime();

  this.passport.authenticate( stratKey, { session: false } )( req, req.res );
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
