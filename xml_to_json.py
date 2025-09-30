import json
from datetime import datetime
import os
import argparse
import logging
from lxml import etree

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def convert_and_save_xml_to_json(xml_file, output_folder):
    """
    Convertit un fichier XML en JSON et l'enregistre dans un dossier spécifié.

    :param xml_file: Chemin du fichier XML à convertir
    :param output_folder: Dossier où sauvegarder les fichiers JSON
    """
    try:
        # Vérifier si le fichier XML existe
        if not os.path.isfile(xml_file):
            logging.error(f"Le fichier XML '{xml_file}' n'existe pas.")
            return

        # Créer le dossier de sortie s'il n'existe pas
        os.makedirs(output_folder, exist_ok=True)

        # Lire et parser le XML avec lxml (mode tolérant)
        parser = etree.XMLParser(recover=True)
        tree = etree.parse(xml_file, parser)
        root = tree.getroot()

        # Fonction récursive pour convertir lxml en dict
        def etree_to_dict(t):
            d = {t.tag: {} if t.attrib else None}
            children = list(t)
            if children:
                dd = {}
                for child in children:
                    child_dict = etree_to_dict(child)
                    for k, v in child_dict.items():
                        if k in dd:
                            if not isinstance(dd[k], list):
                                dd[k] = [dd[k]]
                            dd[k].append(v)
                        else:
                            dd[k] = v
                d = {t.tag: dd}
            if t.attrib:
                d[t.tag].update(('@' + k, v) for k, v in t.attrib.items())
            if t.text and t.text.strip():
                text = t.text.strip()
                if children or t.attrib:
                    d[t.tag]['#text'] = text
                else:
                    d[t.tag] = text
            return d

        data_dict = etree_to_dict(root)

        # Générer un nom de fichier avec un timestamp
        now = datetime.now()
        existing_json_files = [f for f in os.listdir(output_folder) if f.endswith('.json')]
        filename = f"{len(existing_json_files)+1}_{now.strftime('%Y%m%d%H%M%S%f')[:-3]}.json"
        filepath = os.path.join(output_folder, filename)

        # Sauvegarder le contenu JSON dans un fichier
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data_dict, f, indent=4, ensure_ascii=False)

        logging.info(f"Fichier JSON sauvegardé : {filepath}")

    except Exception as general_error:
        logging.error(f"Une erreur inattendue est survenue : {general_error}")

if __name__ == "__main__":
    setup_logging()

    parser = argparse.ArgumentParser(description="Convertir un ou plusieurs fichiers XML en JSON")
    parser.add_argument('xml_files', nargs='+', help='Chemins des fichiers XML à convertir')
    parser.add_argument('output_folder', help='Dossier où sauvegarder les fichiers JSON')
    args = parser.parse_args()

    for xml_file in args.xml_files:
        convert_and_save_xml_to_json(xml_file, args.output_folder)
        
        # python xml_to_json.py fichier1.xml fichier2.xml /chemin/vers/dossier_json
