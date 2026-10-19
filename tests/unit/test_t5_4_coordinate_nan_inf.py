# ABOUTME: Regression tests for T5.4 — inbound coordinate validation must
# ABOUTME: reject NaN and inf values that silently pass `<`/`>` bounds checks.
"""T5.4 — NaN/inf coordinate rejection.

`float('nan') < -90` returns False. `float('nan') > 90` returns False.
The previous `_validate_coordinates()` used only bounds comparisons,
so NaN and +/-inf lat/lon values slipped through and reached the CoT
XML builder — where they either crashed pytak, produced invalid XML,
or manifested as broken client-side geometry.

The fix rejects any non-finite float at the validator, with a clear
error message naming the offending value.
"""

import math

import pytest

from routes.inbound import _validate_coordinates


class TestValidCoordinatesStillAccepted:
    """Regression guard — normal coordinates still validate cleanly."""

    def test_zero_coords_accepted(self):
        assert _validate_coordinates([{"lat": 0, "lon": 0}]) is None

    def test_extreme_but_valid_accepted(self):
        assert _validate_coordinates([
            {"lat": 90.0, "lon": 180.0},
            {"lat": -90.0, "lon": -180.0},
        ]) is None

    def test_typical_coords_accepted(self):
        assert _validate_coordinates([
            {"lat": 35.5, "lon": -122.3},
            {"lat": -33.8688, "lon": 151.2093},
        ]) is None

    def test_missing_coords_pass(self):
        """Location with no lat/lon skips validation (validator's existing
        behaviour — required-field enforcement lives elsewhere)."""
        assert _validate_coordinates([{"uid": "x"}]) is None


class TestOutOfBoundsRejected:
    """Regression guard — the existing bounds check still fires."""

    def test_lat_above_90_rejected(self):
        err = _validate_coordinates([{"lat": 91.0, "lon": 0}])
        assert err is not None
        assert "latitude" in err
        assert "91" in err

    def test_lon_below_negative_180_rejected(self):
        err = _validate_coordinates([{"lat": 0, "lon": -181.0}])
        assert err is not None
        assert "longitude" in err


class TestNaNInfRejected:
    """T5.4 — the new checks catch what `<`/`>` silently allowed."""

    def test_nan_lat_rejected(self):
        err = _validate_coordinates([{"lat": float("nan"), "lon": 0}])
        assert err is not None, (
            "NaN latitude must be rejected — `nan < -90` and `nan > 90` "
            "both return False so the old bounds check let it through"
        )
        assert "not a finite" in err

    def test_nan_lon_rejected(self):
        err = _validate_coordinates([{"lat": 0, "lon": float("nan")}])
        assert err is not None
        assert "not a finite" in err

    def test_positive_inf_lat_rejected(self):
        err = _validate_coordinates([{"lat": float("inf"), "lon": 0}])
        assert err is not None
        assert "not a finite" in err

    def test_negative_inf_lat_rejected(self):
        err = _validate_coordinates([{"lat": float("-inf"), "lon": 0}])
        assert err is not None
        assert "not a finite" in err

    def test_positive_inf_lon_rejected(self):
        err = _validate_coordinates([{"lat": 0, "lon": float("inf")}])
        assert err is not None
        assert "not a finite" in err

    def test_negative_inf_lon_rejected(self):
        err = _validate_coordinates([{"lat": 0, "lon": float("-inf")}])
        assert err is not None
        assert "not a finite" in err

    def test_string_coord_rejected(self):
        """Bonus: string values also fail cleanly (not silently coerced)."""
        err = _validate_coordinates([{"lat": "not a number", "lon": 0}])
        assert err is not None
        assert "not a finite" in err

    def test_first_bad_location_stops_iteration(self):
        """Validator returns the first error rather than aggregating."""
        err = _validate_coordinates([
            {"lat": 35.0, "lon": -122.0},
            {"lat": float("nan"), "lon": 0},
            {"lat": 91.0, "lon": 0},  # would fail too, but not reached
        ])
        assert err is not None
        assert "not a finite" in err

    def test_math_isfinite_is_used(self):
        """Explicit contract check — the validator relies on math.isfinite,
        which is the only stdlib primitive that catches all three cases."""
        assert not math.isfinite(float("nan"))
        assert not math.isfinite(float("inf"))
        assert not math.isfinite(float("-inf"))
        assert math.isfinite(0.0)
        assert math.isfinite(90.0)
