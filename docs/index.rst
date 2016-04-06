.. Network Tools documentation master file, created by
   sphinx-quickstart on Thu Dec 17 14:16:17 2015.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Network Tools API Documentation
===============================

Network tools is a set of RESTful JSON API tools designed to help with everyday work of sysadmins. This API is best with scripts since it's output is JSON.

Access is protected by an IP allow list. If you need to grant access to new IP go to ``settings.py`` and append new IP at the end of ``ALLOWED_IPS`` list.

All endpoints can be rate limited by specifying number of requests in ``settings.py``.


-----------------
API Documentation
-----------------

.. autoflask:: networktoolsapi:app
   :undoc-static:

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. toctree::
   :maxdepth: 2

   source
   changelog