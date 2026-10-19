"""
The IOC database (1.0.0): indicators of compromise collected from IOC
feeds and entered by the team, with their sources, confidence and expiry,
kept in their own SQLite file (ioc.db) next to pantomath.db.

  normalize.py  what a value is and its one canonical spelling
  models.py     ioc.db's tables
  db.py         opening ioc.db (get_ioc_db)
  store.py      adding values: duplicates, sightings, confidence, expiry
  feeds.py      downloading and reading lists published at a URL
  scheduler.py  the IOC feeds' own timer, separate from RSS polling
  routes.py     the IOC database tab, its Settings, and the /api/v1 lookup API

The news side never imports from here except to start the scheduler and
mount the routes, so nothing on the dashboard depends on ioc.db opening.
"""
