# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2019 Bitergia
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# Authors:
#     Alvaro del Castillo <acs@bitergia.com>
#     Valerio Cosentino <valcos@bitergia.com>
#
import logging
import unittest

from base import TestBaseBackend
from grimoire_elk.raw.stackexchange import StackExchangeOcean
from grimoire_elk.enriched.utils import REPO_LABELS


class TestStackexchange(TestBaseBackend):
    """Test Stackexchange backend"""

    connector = "stackexchange"
    ocean_index = "test_" + connector
    ocean_index_anonymized = "test_" + connector + "_anonymized"
    enrich_index = "test_" + connector + "_enrich"
    enrich_index_anonymized = "test_" + connector + "_enrich_anonymized"

    def test_has_identites(self):
        """Test value of has_identities method"""

        enrich_backend = self.connectors[self.connector][2]()
        self.assertTrue(enrich_backend.has_identities())

    def test_items_to_raw(self):
        """Test whether JSON items are properly inserted into ES"""

        result = self._test_items_to_raw()
        self.assertEqual(result['items'], 3)
        self.assertEqual(result['raw'], 3)

    def test_raw_to_enrich(self):
        """Test whether the raw index is properly enriched"""

        result = self._test_raw_to_enrich()
        self.assertEqual(result['raw'], 3)
        self.assertEqual(result['enrich'], 6)

    def test_enrich_repo_labels(self):
        """Test whether the field REPO_LABELS is present in the enriched items"""

        self._test_raw_to_enrich()
        enrich_backend = self.connectors[self.connector][2]()

        for item in self.items:
            eitem = enrich_backend.get_rich_item(item)
            self.assertIn(REPO_LABELS, eitem)

    def test_raw_to_enrich_sorting_hat(self):
        """Test enrich with SortingHat"""

        result = self._test_raw_to_enrich(sortinghat=True)
        self.assertEqual(result['raw'], 3)
        self.assertEqual(result['enrich'], 6)

        enrich_backend = self.connectors[self.connector][2]()

        url = f"{self.es_con}/{self.enrich_index}/_search"
        response = enrich_backend.requests.get(url, verify=False).json()
        for hit in response['hits']['hits']:
            source = hit['_source']
            if 'author_uuid' in source:
                self.assertIn('author_domain', source)
                self.assertIn('author_gender', source)
                self.assertIn('author_gender_acc', source)
                self.assertIn('author_org_name', source)
                self.assertIn('author_bot', source)
                self.assertIn('author_multi_org_names', source)

    def test_raw_to_enrich_projects(self):
        """Test enrich with Projects"""

        result = self._test_raw_to_enrich(projects=True)
        self.assertEqual(result['raw'], 3)
        self.assertEqual(result['enrich'], 6)

    def test_refresh_identities(self):
        """Test refresh identities"""

        result = self._test_refresh_identities()
        # ... ?

    def test_refresh_project(self):
        """Test refresh project field for all sources"""

        result = self._test_refresh_project()
        # ... ?

    def test_perceval_params(self):
        """Test the extraction of perceval params from an URL"""

        url = "https://stackoverflow.com/questions/tagged/ovirt"
        expected_params = [
            '--site', 'stackoverflow.com',
            '--tagged', 'ovirt',
            '--tag', 'https://stackoverflow.com/questions/tagged/ovirt'
        ]
        self.assertListEqual(StackExchangeOcean.get_perceval_params_from_url(url), expected_params)

    def test_copy_raw_fields(self):
        """Test copied raw fields"""

        self._test_raw_to_enrich()
        enrich_backend = self.connectors[self.connector][2]()

        for item in self.items:
            eitem = enrich_backend.get_rich_item(item)
            for attribute in enrich_backend.RAW_FIELDS_COPY:
                if attribute in item:
                    self.assertEqual(item[attribute], eitem[attribute])
                else:
                    self.assertIsNone(eitem[attribute])

    def test_items_to_raw_anonymized(self):
        """Test whether JSON items are properly inserted into ES anonymized"""

        result = self._test_items_to_raw_anonymized()

        self.assertEqual(result['items'], 3)
        self.assertEqual(result['raw'], 3)

        item = self.items[0]['data']
        self.assertEqual(item['owner']['display_name'], '80490d00f668dde48d4e0ce62142c8a2ac9a1465')
        self.assertEqual(item['owner']['user_id'], '182b39d390fc9fde7594184cbe6e6f8653cfd5b2')
        self.assertEqual(item['owner']['link'], '')
        self.assertEqual(item['owner']['profile_image'], '')
        self.assertEqual(len(item['comments']), 0)
        self.assertEqual(item['answers'][0]['owner']['display_name'], '0d2244465bfc8b636bf1fbe74912cc2c748b42e4')
        self.assertEqual(item['answers'][0]['owner']['user_id'], 'c7b7c5dea6f6a1a4531bf491b207d123ca41da4c')
        self.assertEqual(item['answers'][0]['owner']['link'], '')
        self.assertEqual(item['answers'][0]['owner']['profile_image'], '')
        self.assertEqual(len(item['answers'][0]['comments']), 0)

    def test_raw_to_enrich_anonymized(self):
        """Test whether the raw index is properly enriched"""

        result = self._test_raw_to_enrich_anonymized()

        self.assertEqual(result['raw'], 3)
        self.assertEqual(result['enrich'], 6)

        enrich_backend = self.connectors[self.connector][2]()

        item = self.items[0]
        eitem = enrich_backend.get_rich_item(item)
        self.assertEqual(eitem['author'], '80490d00f668dde48d4e0ce62142c8a2ac9a1465')
        self.assertEqual(eitem['author_link'], '')


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    unittest.main(warnings='ignore')
