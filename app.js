var util = require('util'),
  express = require('express'),
  googleapis = require('googleapis'),
  request = require('request'),
  sqlite3 = require('sqlite3'),
  db = new sqlite3.Database('database.db'),
  settings = {
    server: {
      hostname: 'mktgdept.herokuapp.com',
      port: process.env.PORT || '5555'
    },
    google: {
      client_id: '000000000000.apps.googleusercontent.com',
      client_secret: 'bbbbbbbbbbbbbbbbbbbbbbbb'
    }
  },
  OAuth2Client = googleapis.OAuth2Client,
  getOAuth2Client = function(credentials) {
    var client = new OAuth2Client(settings.google.client_id, settings.google.client_secret, 'http://' + settings.server.hostname + '/oauth2callback');
    if(credentials)
      client.credentials = credentials;
    return client;
  },
  template = function(text, title, image) {
    if(image)
      return '<article class="photo"><img src="' + image + '" width="100%" height="100%"><div class="photo-overlay"></div><section><div class="text-auto-size">' + text + '</div></section><footer><p class="yellow">' + title + '</p></footer></article>';
    return '<article><section><div class="text-auto-size">' + text + '</div></section><footer><p class="yellow">' + title + '</p></footer></article>';
  },
  app = express();

app.configure(function() {
  app.use(express.logger('dev'));
  app.use(express.bodyParser());
  app.use(express.static(__dirname + '/public'));
  app.set('views', __dirname + '/views');
  app.set('view engine', 'jade');
  app.use(express.cookieParser("it's a secret to everybody"));
  app.use(express.session({ secret: "it's a secret to everybody" }));
  db.run('CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, token TEXT, refresh TEXT, active INTEGER)');
  db.run('CREATE TABLE IF NOT EXISTS snaps (id TEXT PRIMARY KEY, sender TEXT, recipient TEXT, destination TEXT)');
});

app.get('/', function(req, res) {
  if(!req.session.user)
    res.render('index');
  else {
    db.get('SELECT * FROM users WHERE id = ?', req.session.user, function(err, row) {
      if(!row) {
        delete req.session.user;
        return res.redirect('/');
      }
      var oauth2Client = getOAuth2Client({ access_token: row.token, refresh_token: row.refresh });
      googleapis.discover('mirror', 'v1').execute(function(err, client) {
        // subscribe to the app's timeline activity
        client.mirror.subscriptions.insert({
          callbackUrl: 'https://mirrornotifications.appspot.com/forward?url=http://' + settings.server.hostname + '/subcallback',
          collection: 'timeline',
          userToken: req.session.user
        }).withAuthClient(oauth2Client).execute(function(err, result) {
          console.log('mirror.subscriptions.insert', util.inspect(result));
        });
        // insert the snapglass contact
        client.mirror.contacts.insert({
          displayName: 'Snapglass',
          id: 'snapglass',
          imageUrls: [ 'http://' + settings.server.hostname + '/contact_image.png' ],
          acceptTypes: [ 'image/*' ]
        }).withAuthClient(oauth2Client).execute(function(err, result) {
          console.log('mirror.contacts.insert', util.inspect(result));
        });
        // insert the snapglass settings card
        client.mirror.timeline.insert({
          html: template('Snapglass is active.', 'Snapglass', 'http://' + settings.server.hostname + '/contact_image.png'),
          menuItems: [
            {
              id: 'pause',
              action: 'CUSTOM',
              values: [
                {
                  displayName: 'Pause',
                  iconUrl: 'http://' + settings.server.hostname + '/pause.png'
                }
              ]
            },
            {
              action: 'TOGGLE_PINNED'
            },
            {
              action: 'DELETE'
            }
          ]
        }).withAuthClient(oauth2Client).execute(function(err, result) {
          console.log('mirror.timeline.insert', util.inspect(result));
        });
      });
    });
    res.render('user');
  }
});

app.get('/login', function(req, res) {
  var oauth2Client = getOAuth2Client();
  // ask the user to allow access to their timeline activity and google profile
  res.redirect(oauth2Client.generateAuthUrl({
    access_type: 'offline',
    approval_prompt: 'force',
    scope: [
      'https://www.googleapis.com/auth/glass.timeline',
      'https://www.googleapis.com/auth/userinfo.profile'
    ].join(' ')
  }));
});

app.get('/oauth2callback', function(req, res) {
  if(!req.query.code)
    return res.redirect('/');
  var oauth2Client = getOAuth2Client();
  oauth2Client.getToken(req.query.code, function(err, tokens) {
    if(!tokens)
      return res.redirect('/');
    oauth2Client.credentials = tokens;
    googleapis.discover('oauth2', 'v2').execute(function(err, client) {
      // get the user's info and save it in the database, update it if they're already in there
      client.oauth2.userinfo.get().withAuthClient(oauth2Client).execute(function(err, result) {
        req.session.user = result.id;
        db.get('SELECT id FROM users WHERE id = ?', result.id, function(err, row) {
          if(row)
            db.run('UPDATE users SET token = ?, refresh = ?, active = 1 WHERE id = ?', [ tokens.access_token, tokens.refresh_token, result.id ], function(err) {
              res.redirect('/');
            });
          else
            db.run('INSERT INTO users VALUES (?, ?, ?, ?)', [ result.id, tokens.access_token, tokens.refresh_token, 1 ], function(err) {
              res.redirect('/');
            });
        });
      });
    });
  });
});

app.post('/subcallback', function(req, res) {
  res.send(200);
  var user = req.body.userToken,
    id = req.body.itemId;
  console.log('/subcallback', util.inspect(req.body));
  // someone shared a photo!
  if(req.body.operation == 'INSERT' && req.body.userActions[0].type == 'SHARE') {
    // lookup who it was
    db.get('SELECT * FROM users WHERE id = ?', user, function(err, row) {
      if(!row)
        return;
      var oauth2Client = getOAuth2Client({ access_token: row.token, refresh_token: row.refresh });
      googleapis.discover('mirror', 'v1').execute(function(err, client) {
        // get the timeline item shared with the app
        client.mirror.timeline.get({ id: id }).withAuthClient(oauth2Client).execute(function(err, result) {
          console.log('mirror.timeline.get', util.inspect(result));
          if(result.attachments && result.attachments.length) {
            var contentType = result.attachments[0].contentType;
            // download the photo that was shared
            request({
              method: 'GET',
              uri: result.attachments[0].contentUrl,
              headers: {
                'Authorization': [ oauth2Client.credentials.token_type, oauth2Client.credentials.access_token ].join(' ')
              },
              encoding: 'binary'
            }, function(err, req, body) {
              // select a random user
              db.get('SELECT * FROM users WHERE id != ? AND active = 1 ORDER BY RANDOM() LIMIT 1', user, function(err, row) {
                if(row) {
                  var oauth2Client2 = getOAuth2Client({ access_token: row.token, refresh_token: row.refresh });
                  // make sure their token is fresh
                  oauth2Client2.refreshAccessToken(function(err) {
                    if(!err)
                      // insert the shared photo in their timeline
                      request({
                        method: 'POST',
                        uri: 'https://www.googleapis.com/upload/mirror/v1/timeline',
                        headers: {
                          'Authorization': [ oauth2Client2.credentials.token_type, oauth2Client2.credentials.access_token ].join(' '),
                          'Content-Type': 'multipart/related;'
                        },
                        multipart: [
                          {
                            'Content-Type': 'application/json; charset=UTF-8',
                            body: JSON.stringify({
                              text: 'Snapglass' + (result.text ? ': ' + result.text : ''),
                              menuItems: [
                                {
                                  action: 'REPLY'
                                },
                                {
                                  action: 'DELETE'
                                }
                              ],
                              notification: {
                                level: 'DEFAULT'
                              }
                            })
                          },
                          {
                            'Content-Type': contentType,
                            'Content-Transfer-Encoding': 'binary',
                            body: new Buffer(body, 'binary')
                          }
                        ]
                      }, function(err, req, body) {
                        body = JSON.parse(body);
                        console.log('mirror.timeline.insert', util.inspect(body));
                        // insert the share into the database
                        db.run('INSERT INTO snaps VALUES (?, ?, ?, ?)', [ id, user, row.id, body.id ]);
                        // notify the sender it has been received
                        client.mirror.timeline.patch({ id: id }, {
                          text: 'Snapglass' + (result.text ? ': ' + result.text : ''),
                          notification: {
                            level: 'DEFAULT'
                          }
                        }).withAuthClient(oauth2Client).execute(function(err, result) {
                          console.log('mirror.timeline.patch', util.inspect(result));
                        });
                      });
                  });
                }
              });
            });
          }
        });
      });
    });
  }
  // someone replied to a photo!
  if(req.body.operation == 'INSERT' && req.body.userActions[0].type == 'REPLY') {
    // lookup who it was
    db.get('SELECT * FROM users WHERE id = ?', user, function(err, row) {
      if(!row)
        return;
      var oauth2Client = getOAuth2Client({ access_token: row.token, refresh_token: row.refresh });
      googleapis.discover('mirror', 'v1').execute(function(err, client) {
        // get the timeline item shared with the app
        client.mirror.timeline.get({ id: id }).withAuthClient(oauth2Client).execute(function(err, result) {
          console.log('mirror.timeline.get', util.inspect(result));
          var text = result.text, destinationId = result.inReplyTo;
          // lookup who the sender was
          db.get('SELECT * FROM snaps WHERE recipient = ? AND destination = ?', [ user, destinationId ], function(err, snap) {
            if(!snap)
              return;
            db.get('SELECT * FROM users WHERE id = ?', snap.sender, function(err, row) {
              var oauth2Client2 = getOAuth2Client({ access_token: row.token, refresh_token: row.refresh });
              // notify the sender of the reply
              client.mirror.timeline.insert({
                bundleId: snap.id,
                isBundleCover: true,
                html: template(text, 'Snapglass'),
              }).withAuthClient(oauth2Client2).execute(function(err, result) {
                // bundle the original share with the reply
                client.mirror.timeline.patch({
                  id: snap.id
                }, {
                  bundleId: snap.id,
                  sourceItemId: result.id
                }).withAuthClient(oauth2Client2).execute();
              });
            });
            // update the reply card so it can be deleted
            client.mirror.timeline.patch({
              id: id
            }, {
              html: template(text, 'Snapglass'),
              bundleId: destinationId,
              isBundleCover: true,
              menuItems: [
                {
                  action: 'DELETE'
                }
              ]
            }).withAuthClient(oauth2Client).execute();
            // bundle the photo with the reply and disable additional replies
            client.mirror.timeline.patch({
              id: destinationId
            }, {
              bundleId: destinationId,
              sourceItemId: id,
              menuItems: [
                {
                  action: 'DELETE'
                }
              ]
            }).withAuthClient(oauth2Client).execute();
          });
        });
      });
    });
  }
  // someone deleted something!
  if(req.body.operation == 'DELETE') {
    // lookup who it was
    db.get('SELECT * FROM users WHERE id = ?', user, function(err, row) {
      if(!row)
        return;
      var oauth2Client = getOAuth2Client({ access_token: row.token, refresh_token: row.refresh });
      googleapis.discover('mirror', 'v1').execute(function(err, client) {
        // get the item that was deleted
        client.mirror.timeline.get({ id: id }).withAuthClient(oauth2Client).execute(function(err, result) {
          console.log('mirror.timeline.get', util.inspect(result));
          // if it was part of a bundle, delete the remaining card
          if(result.sourceItemId)
            client.mirror.timeline.delete({ id: result.sourceItemId }).withAuthClient(oauth2Client).execute();
          // see if the item deleted was the orignal photo
          db.get('SELECT * FROM snaps WHERE id = ? OR id = ? LIMIT 1', [ id, result.sourceItemId ], function(err, snap) {
            if(!snap)
              return;
            // disable replies if it was
            db.get('SELECT * FROM users WHERE id = ?', snap.recipient, function(err, row) {
              var oauth2Client2 = getOAuth2Client({ access_token: row.token, refresh_token: row.refresh });
              client.mirror.timeline.patch({
                id: snap.destination
              }, {
                menuItems: [
                  {
                    action: 'DELETE'
                  }
                ],
                notification: null
              }).withAuthClient(oauth2Client2).execute();
            });
          });
        });
      });
    });
  }
  // someone paused or resumed snapglass!
  if(req.body.operation == 'UPDATE' && req.body.userActions[0].type == 'CUSTOM') {
    // lookup who it was
    db.get('SELECT * FROM users WHERE id = ?', user, function(err, row) {
      if(!row)
        return;
      var active = 'resume' == req.body.userActions[0].payload;
      // disable or enable them in the database
      db.run('UPDATE users SET active = ? WHERE id = ?', [ active ? 1 : 0, user ]);
      var oauth2Client = getOAuth2Client({ access_token: row.token, refresh_token: row.refresh });
      googleapis.discover('mirror', 'v1').execute(function(err, client) {
        // update the settings card
        client.mirror.timeline.patch({ id: id }, {
          html: template('Snapglass is ' + (active ? ' active.' : ' paused.'), 'Snapglass', 'http://' + settings.server.hostname + '/contact_image.png'),
          menuItems: [
            active ? {
              id: 'pause',
              action: 'CUSTOM',
              values: [
                {
                  displayName: 'Pause',
                  iconUrl: 'http://' + settings.server.hostname + '/pause.png'
                }
              ]
            } : {
              id: 'resume',
              action: 'CUSTOM',
              values: [
                {
                  displayName: 'Resume',
                  iconUrl: 'http://' + settings.server.hostname + '/resume.png'
                }
              ]
            },
            {
              action: 'TOGGLE_PINNED'
            },
            {
              action: 'DELETE'
            }
          ]
        }).withAuthClient(oauth2Client).execute();
      });
    });
  }
});

app.listen(settings.server.port);