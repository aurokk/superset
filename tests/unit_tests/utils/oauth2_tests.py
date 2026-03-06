# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# pylint: disable=invalid-name, disallowed-name

from datetime import datetime

from freezegun import freeze_time
from pytest_mock import MockerFixture

from superset.utils.oauth2 import (
    get_oauth2_access_token,
    get_upstream_provider_token,
    save_user_provider_token,
)


def test_get_oauth2_access_token_base_no_token(mocker: MockerFixture) -> None:
    """
    Test `get_oauth2_access_token` when there's no token.
    """
    db = mocker.patch("superset.utils.oauth2.db")
    db_engine_spec = mocker.MagicMock()
    db.session.query().filter_by().one_or_none.return_value = None

    assert get_oauth2_access_token({}, 1, 1, db_engine_spec) is None


def test_get_oauth2_access_token_base_token_valid(mocker: MockerFixture) -> None:
    """
    Test `get_oauth2_access_token` when the token is valid.
    """
    db = mocker.patch("superset.utils.oauth2.db")
    db_engine_spec = mocker.MagicMock()
    token = mocker.MagicMock()
    token.access_token = "access-token"  # noqa: S105
    token.access_token_expiration = datetime(2024, 1, 2)
    db.session.query().filter_by().one_or_none.return_value = token

    with freeze_time("2024-01-01"):
        assert get_oauth2_access_token({}, 1, 1, db_engine_spec) == "access-token"


def test_get_oauth2_access_token_base_refresh(mocker: MockerFixture) -> None:
    """
    Test `get_oauth2_access_token` when the token needs to be refreshed.
    """
    db = mocker.patch("superset.utils.oauth2.db")
    db_engine_spec = mocker.MagicMock()
    db_engine_spec.get_oauth2_fresh_token.return_value = {
        "access_token": "new-token",
        "expires_in": 3600,
    }
    token = mocker.MagicMock()
    token.access_token = "access-token"  # noqa: S105
    token.access_token_expiration = datetime(2024, 1, 1)
    token.refresh_token = "refresh-token"  # noqa: S105
    db.session.query().filter_by().one_or_none.return_value = token

    with freeze_time("2024-01-02"):
        assert get_oauth2_access_token({}, 1, 1, db_engine_spec) == "new-token"

    # check that token was updated
    assert token.access_token == "new-token"  # noqa: S105
    assert token.access_token_expiration == datetime(2024, 1, 2, 1)
    db.session.add.assert_called_with(token)


def test_get_oauth2_access_token_base_no_refresh(mocker: MockerFixture) -> None:
    """
    Test `get_oauth2_access_token` when token is expired and there's no refresh.
    """
    db = mocker.patch("superset.utils.oauth2.db")
    db_engine_spec = mocker.MagicMock()
    token = mocker.MagicMock()
    token.access_token = "access-token"  # noqa: S105
    token.access_token_expiration = datetime(2024, 1, 1)
    token.refresh_token = None
    db.session.query().filter_by().one_or_none.return_value = token

    with freeze_time("2024-01-02"):
        assert get_oauth2_access_token({}, 1, 1, db_engine_spec) is None

    # check that token was deleted
    db.session.delete.assert_called_with(token)


# ---- Upstream provider token tests ----


def test_save_user_provider_token_creates_new(mocker: MockerFixture) -> None:
    """
    Test that `save_user_provider_token` creates a new row when none exists.
    """
    db = mocker.patch("superset.utils.oauth2.db")
    mocker.patch(
        "superset.utils.oauth2.UpstreamOAuthToken",
        autospec=True,
    )
    db.session.query().filter_by().one_or_none.return_value = None

    save_user_provider_token(
        user_id=1,
        provider="keycloak",
        token_response={"access_token": "tok", "expires_in": 3600},  # noqa: S106
    )

    db.session.add.assert_called_once()
    db.session.commit.assert_called_once()


def test_save_user_provider_token_updates_existing(mocker: MockerFixture) -> None:
    """
    Test that `save_user_provider_token` updates an existing row.
    """
    db = mocker.patch("superset.utils.oauth2.db")
    existing = mocker.MagicMock()
    db.session.query().filter_by().one_or_none.return_value = existing

    save_user_provider_token(
        user_id=1,
        provider="keycloak",
        token_response={"access_token": "new-tok", "expires_in": 3600},  # noqa: S106
    )

    assert existing.access_token == "new-tok"  # noqa: S105
    db.session.add.assert_called_once_with(existing)
    db.session.commit.assert_called_once()


def test_get_upstream_provider_token_no_record(mocker: MockerFixture) -> None:
    """
    Test `get_upstream_provider_token` returns None when no record exists.
    """
    db = mocker.patch("superset.utils.oauth2.db")
    db.session.query().filter_by().one_or_none.return_value = None

    result = get_upstream_provider_token("keycloak", 1)

    assert result is None


def test_get_upstream_provider_token_valid(mocker: MockerFixture) -> None:
    """
    Test `get_upstream_provider_token` returns the access token when it is valid.
    """
    db = mocker.patch("superset.utils.oauth2.db")
    token = mocker.MagicMock()
    token.access_token = "valid-token"  # noqa: S105
    token.access_token_expiration = datetime(2024, 1, 2)
    db.session.query().filter_by().one_or_none.return_value = token

    with freeze_time("2024-01-01"):
        result = get_upstream_provider_token("keycloak", 1)

    assert result == "valid-token"


def test_get_upstream_provider_token_expired_no_refresh(mocker: MockerFixture) -> None:
    """
    Test `get_upstream_provider_token` deletes the record and returns None when
    the token is expired and there is no refresh token.
    """
    db = mocker.patch("superset.utils.oauth2.db")
    token = mocker.MagicMock()
    token.access_token = "expired-token"  # noqa: S105
    token.access_token_expiration = datetime(2024, 1, 1)
    token.refresh_token = None
    db.session.query().filter_by().one_or_none.return_value = token

    with freeze_time("2024-01-02"):
        result = get_upstream_provider_token("keycloak", 1)

    assert result is None
    db.session.delete.assert_called_once_with(token)
    db.session.commit.assert_called_once()


def test_get_upstream_provider_token_expired_calls_refresh(
    mocker: MockerFixture,
) -> None:
    """
    Test `get_upstream_provider_token` calls the refresh path when the token
    is expired but a refresh token is present.
    """
    db = mocker.patch("superset.utils.oauth2.db")
    token = mocker.MagicMock()
    token.access_token = "expired-token"  # noqa: S105
    token.access_token_expiration = datetime(2024, 1, 1)
    token.refresh_token = "refresh-tok"  # noqa: S105
    db.session.query().filter_by().one_or_none.return_value = token

    refresh_mock = mocker.patch(
        "superset.utils.oauth2._refresh_upstream_provider_token",
        return_value="new-token",
    )

    with freeze_time("2024-01-02"):
        result = get_upstream_provider_token("keycloak", 1)

    assert result == "new-token"
    refresh_mock.assert_called_once_with(token, "keycloak")
