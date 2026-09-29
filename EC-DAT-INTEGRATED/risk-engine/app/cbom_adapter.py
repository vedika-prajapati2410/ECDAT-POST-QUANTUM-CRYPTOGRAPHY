"""
Adapter for converting the CycloneDX CBOM produced by Backend 1
into the artefact format used internally by Backend 2.
"""

import hashlib


def adapt_cyclonedx_cbom(cyclonedx_cbom: dict) -> list:
    """
    Convert Backend 1 CycloneDX CBOM into Backend 2 artefacts.
    """

    if not isinstance(cyclonedx_cbom, dict):
        raise ValueError("CycloneDX CBOM must be a JSON object.")

    components = cyclonedx_cbom.get("components")

    if not isinstance(components, list):
        raise ValueError(
            "CycloneDX CBOM must contain a 'components' array."
        )

    artefacts = []

    for index, component in enumerate(components):

        if not isinstance(component, dict):
            continue

        component_type = component.get("type")
        name = component.get(
            "name",
            f"component-{index}"
        )

        properties = _read_properties(
            component.get("properties", [])
        )

        file_path = properties.get(
            "filePath",
            "unknown"
        )

        line_number = properties.get(
            "lineNumber"
        )

        crypto_properties = component.get(
            "cryptoProperties",
            {}
        )

        algorithm_properties = crypto_properties.get(
            "algorithmProperties",
            {}
        )

        # -----------------------------------------
        # Cryptographic asset
        # -----------------------------------------
        if component_type == "cryptographic-asset":

            algorithm = algorithm_properties.get(
                "algorithm"
            )

            if not algorithm:
                algorithm = name.replace(
                    " usage",
                    ""
                )

            key_length = _parse_key_length(
                algorithm_properties.get(
                    "parameterSetIdentifier"
                )
            )

            primitive = algorithm_properties.get(
                "primitive"
            )

            artefact = {
                "id": _make_id(
                    name,
                    algorithm,
                    file_path,
                    line_number
                ),
                "name": name,
                "type": crypto_properties.get(
                    "assetType",
                    "algorithm"
                ),
                "algorithm": algorithm,
                "location": _format_location(
                    file_path,
                    line_number
                ),
                "key_length": key_length,
                "primitive": primitive,
                "confidence": "low"
            }

            artefacts.append(artefact)

        # -----------------------------------------
        # Dependency/library
        # -----------------------------------------
        elif component_type == "library":

            version = component.get(
                "version"
            )

            artefact = {
                "id": _make_id(
                    name,
                    name,
                    file_path,
                    None
                ),
                "name": name,
                "type": "library",
                "algorithm": name,
                "location": file_path,
                "library_name": name,
                "library_version": version,
                "confidence": "medium"
            }

            artefacts.append(artefact)

    return artefacts


def _read_properties(properties: list) -> dict:
    """
    Convert CycloneDX properties array into a dictionary.
    """

    result = {}

    if not isinstance(properties, list):
        return result

    for property_item in properties:

        if not isinstance(property_item, dict):
            continue

        name = property_item.get("name")
        value = property_item.get("value")

        if name:
            result[name] = value

    return result


def _parse_key_length(value):
    """
    Convert key length from string to integer.
    """

    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _format_location(
        file_path: str,
        line_number):

    if line_number:
        return f"{file_path}:line:{line_number}"

    return file_path


def _make_id(
        name,
        algorithm,
        file_path,
        line_number):

    raw = (
        f"{name}|"
        f"{algorithm}|"
        f"{file_path}|"
        f"{line_number}"
    )

    return hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()[:16]