import json
import xmltodict
from datetime import datetime
import os
import argparse
import logging

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
#d
def convert_and_save_xml_to_json(xml_file, output_folder):
    """
    Convertit un fichier XML en JSON et l'enregistre dans un dossier spécifié.

    :param xml_file: Chemin du fichier XML à convertir
    :param output_folder: Dossier où sauvegarder les fichiers JSON
    """
    try:
        if not os.path.isfile(xml_file):
            logging.error(f"Le fichier XML '{xml_file}' n'existe pas.")
            return
        os.makedirs(output_folder, exist_ok=True)
        with open(xml_file, 'r', encoding='utf-8') as f:
            xml_content = f.read()
        try:
            data_dict = xmltodict.parse(xml_content)
        except Exception as e:
            logging.error(f"Erreur lors de la conversion XML -> dict : {e}")
            return
        json_content = json.dumps(data_dict, indent=4, sort_keys=True, ensure_ascii=False)
        now = datetime.now()
        existing_json_files = [f for f in os.listdir(output_folder) if f.endswith('.json')]
        filename = f"{len(existing_json_files)+1}_{now.strftime('%Y%m%d%H%M%S%f')[:-3]}.json"
        filepath = os.path.join(output_folder, filename)
        with open(filepath, 'w', encoding='utf-8') as json_file:
            json_file.write(json_content)
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
