import xml.etree.ElementTree as ET
import uuid
from datetime import datetime

def create_ioc_from_hashes(input_filename, output_filename):
    # Namespace and schema details
    ns = "http://schemas.mandiant.com/2010/ioc"
    ET.register_namespace('', ns)  # Register the default namespace

    # Read the SHA256 hashes from the input file
    with open(input_filename, 'r') as file:
        hashes = [line.strip() for line in file if line.strip()]

    # Root element with necessary attributes and schema location
    root_attribs = {
        "{http://www.w3.org/2001/XMLSchema-instance}schemaLocation": f"{ns} http://schemas.mandiant.com/2010/ioc/ioc.xsd",
        "id": str(uuid.uuid4()),
        "last-modified": datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    }
    ioc_root = ET.Element("{http://schemas.mandiant.com/2010/ioc}ioc", root_attribs)

    # Metadata elements
    ET.SubElement(ioc_root, "{http://schemas.mandiant.com/2010/ioc}short_description").text = "IoC for Webshell"
    ET.SubElement(ioc_root, "{http://schemas.mandiant.com/2010/ioc}authored_by").text = "LunarFang"
    ET.SubElement(ioc_root, "{http://schemas.mandiant.com/2010/ioc}authored_date").text = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    ET.SubElement(ioc_root, "{http://schemas.mandiant.com/2010/ioc}links")

    # Definition and Indicator elements
    definition = ET.SubElement(ioc_root, "{http://schemas.mandiant.com/2010/ioc}definition")
    indicator = ET.SubElement(definition, "{http://schemas.mandiant.com/2010/ioc}Indicator", {"operator": "OR", "id": str(uuid.uuid4())})

    # Adding each hash as an IndicatorItem
    for hash_value in hashes:
        indicator_item = ET.SubElement(indicator, "{http://schemas.mandiant.com/2010/ioc}IndicatorItem", {
            "id": str(uuid.uuid4()),
            "condition": "is"
        })
        
        ET.SubElement(indicator_item, "{http://schemas.mandiant.com/2010/ioc}Context", {
            "document": "FileItem",
            "search": "FileItem/Sha256sum",
            "type": "mir"
        })

        ET.SubElement(indicator_item, "{http://schemas.mandiant.com/2010/ioc}Content", {
            "type": "string"
        }).text = hash_value

    # Write to file with UTF-8 encoding to ensure all characters are handled correctly
    tree = ET.ElementTree(ioc_root)
    tree.write(output_filename, encoding="utf-8", xml_declaration=True)

def main():
    input_file = input("Enter the path to the text file containing the SHA256 hashes: ")
    output_file = input("Enter the name of the output IOC file: ")
    create_ioc_from_hashes(input_file, output_file)
    print(f"IOC file has been created: {output_file}")

if __name__ == "__main__":
    main()
