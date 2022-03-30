import configparser
import math
import os
import sys
from bitarray import bitarray
from getopt import getopt, GetoptError
from io import BufferedWriter
from typing import Union
from vivify import Vivify


class PduGenerator(object):
    """
    About
    -----
    Generates PDUs according to the CCSDS 727.0-B-4 CFDP Standard. This utility
    is NOT designed to be a full CFDP implementation. It mimics the functionality
    of a CFDP Processor's PUT functionality.

    Configuration
    -------------
    PDU_Generator requires a pdu_generator.cfg configuration file. An example one
    has been included with this module. It uses the "-c <file>" command line
    argument to receive the configuration file at runtime. The PDU_Generator
    constructor expects the python process's command line arguments as a parameter.

    Author
    ------
    James Brennan
    """

    config_file: str
    source_file: str
    source_entity_id: int
    destination_entity_id: int
    destination_file_name: str
    transaction_sequence_number: int
    pdu_file_data_chunk_size: int

    def __init__(self, argv: list[str] = None) -> None:
        Vivify.initialize()
        PduGenerator.__parse_args(self, argv)
        PduGenerator.__parse_config_file(self)


    def __parse_args(self, argv: list[str] = None) -> None:
        if argv:
            try:
                opts, args = getopt(argv, "c:")
                opts = dict(opts)

                if "-c" in opts:
                    self.config_file = opts["-c"]
                else:
                    Vivify.vivify("{!} {R}ERROR{W}: Missing {C}configuration {W}file!")
                    PduGenerator.__display_args(self, exit=True)

            except GetoptError:
                Vivify.vivify("{!} {R}ERROR{W}: Unsupported arguments provided!")
                PduGenerator.__display_args(self, exit=True)
        else:
            Vivify.vivify("{!} {R}ERROR{W}: The required {Y}-c {W}argument was not provided!")
            PduGenerator.__display_args(self, exit=True)


    def __parse_config_file(self) -> None:
        Vivify.vivify("{*} {M}Parsing {W}the {C}configuration {W}file...")
        config = configparser.ConfigParser()

        try:
            config.read(self.config_file)
            if not "CONFIG" in config:
                PduGenerator.__display_exit_message(self, "{!} {R}ERROR{W}: Missing {Y}CONFIG {W}section in the {C}configuration {W}file!", 1)
        except configparser.Error:
            PduGenerator.__display_exit_message(self, "{!} {R}ERROR{W}: Unable to load {C}configuration {W}file!", 1)

        if config.get("CONFIG", "source_file", fallback=False):
            self.source_file = config.get("CONFIG", "source_file")
            if os.path.isfile(self.source_file):
                Vivify.vivify("{+} {G}Parsed {W}property {C}source_file {W}as: {G}" + self.source_file)
            else:
                PduGenerator.__display_exit_message(self, "{!} {R}ERROR{W}: The {Y}source_file {W}provided in the {C}configuration {W}file does not exist!")
        else:
            PduGenerator.__display_exit_message(self, "{!} {R}ERROR{W}: Missing {Y}source_file {W}property in {C}configuration {W}file!")

        if config.get("CONFIG", "source_entity_id", fallback=False):
            self.source_entity_id = config.getint("CONFIG", "source_entity_id")
            Vivify.vivify("{+} {G}Parsed {W}property {C}source_entity_id {W}as: {G}" + str(self.source_entity_id))
        else:
            self.source_entity_id = int(1)
            Vivify.vivify("{?} {Y}Defaulted {W}property {C}source_entity_id {W}to: {Y}" + str(self.source_entity_id))

        if config.get("CONFIG", "destination_entity_id", fallback=False):
            self.destination_entity_id = config.getint("CONFIG", "destination_entity_id")
            Vivify.vivify("{+} {G}Parsed {W}property {C}destination_entity_id {W}as: {G}" + str(self.destination_entity_id))
        else:
            self.destination_entity_id = int(2)
            Vivify.vivify("{?} {Y}Defaulted {W}property {C}destination_entity_id {W}to: {Y}" + str(self.destination_entity_id))

        if config.get("CONFIG", "destination_file_name", fallback=False):
            self.destination_file_name = config.get("CONFIG", "destination_file_name")
            Vivify.vivify("{+} {G}Parsed {W}property {C}destination_file_name {W}as: {G}" + str(self.destination_file_name))
        else:
            self.destination_file_name = os.path.basename(self.source_file)
            Vivify.vivify("{?} {Y}Defaulted {W}property {C}destination_file_name {W}to: {Y}" + self.destination_file_name)

        if config.get("CONFIG", "transaction_sequence_number", fallback=False):
            self.transaction_sequence_number = config.getint("CONFIG", "transaction_sequence_number")
            Vivify.vivify("{+} {G}Parsed {W}property {C}transaction_sequence_number {W}as: {G}" + str(self.transaction_sequence_number))
        else:
            self.transaction_sequence_number = int(42)
            Vivify.vivify("{?} {Y}Defaulted {W}property {C}transaction_sequence_number {W}to: {Y}" + str(self.transaction_sequence_number))

        if config.get("CONFIG", "pdu_file_data_chunk_size", fallback=False):
            self.pdu_file_data_chunk_size = config.getint("CONFIG", "pdu_file_data_chunk_size")
            if self.pdu_file_data_chunk_size > 65531:
                PduGenerator.__display_exit_message(self, "{!} {R}ERROR{W}: The provided {C}pdu_file_data_chunk_size {W}property exceeded the allowed maximum: {Y}65,531")
            Vivify.vivify("{+} {G}Parsed {W}property {C}pdu_file_data_chunk_size {W}as: {G}" + str(self.pdu_file_data_chunk_size))
        else:
            self.pdu_file_data_chunk_size = int(1000)
            Vivify.vivify("{?} {Y}Defaulted {W}property {C}pdu_file_data_chunk_size {W}to: {Y}" + str(self.pdu_file_data_chunk_size))


    def __display_exit_message(self, message: str, exit_code: int = 0) -> None:
        Vivify.vivify(message)
        sys.exit(exit_code)


    def __display_args(self, exit: bool = False) -> None:
        if exit:
            PduGenerator.__display_exit_message(self, "{*} {W}PDU Generator usage: {G}python pdu_generator.py -c {C}[config_file]{W}")
        else:
            Vivify.vivify("{*} {W}PDU Generator usage: {G}python pdu_generator.py {C}[config_file]{W}")


    def __to_bytes(self, num: int, length: int) -> bytearray:
        """
        Used to convert an integer to an n-byte representation of itself.
        """
        byte_array = bytearray(length)
        for i in range(length):
            byte_array[i] = num & 0xff
            num >>= 8
        if num:
            raise OverflowError()
        byte_array.reverse()
        return byte_array


    def __to_bits(self, num: int, length: int, bit_array: bitarray) -> None:
        """
        Used to convert an integer to an n-bit representation of itself.
        """
        num_bin_str = bin(num)[2:]
        if len(num_bin_str) < length:
            num_bin_str = ("0" * (length - len(num_bin_str))) + num_bin_str
        for character in num_bin_str:
            bit_array.append(int(character))


    def __get_int_byte_size(self, num: int) -> int:
        """
        Gets the number of bytes needed to represent the specified integer.
        """
        byte_size = 0
        while num / 255 > 1:
            num /= 255
            byte_size += 1
        return byte_size + 1


    def __pretty_hex(self, value: Union[bitarray, bytearray]) -> str:
        if isinstance(value, bitarray):
            return value.tobytes().hex().upper()
        else:
            hex = value.hex(" ").upper().split()
            if len(hex) > 8:
                return " ".join(hex[-8:]) + " (truncated)"
            return " ".join(hex) 


    def __output(self, value: Union[bitarray, bytearray], file: BufferedWriter) -> None:
        """
        Convenience method for writing bitarray, bytearray, bytes, and str values to a file.
        """
        if isinstance(value, bitarray):
            value.tofile(file)
        else:
            file.write(value)


    def __generate_pdu_header(self, pdu_type: int, pdu_data_length: int) -> list[Union[bitarray, bytearray]]:
        """
        Generates the header bytes for all types of PDUs.
        """
        Vivify.vivify("{*} {M}Generating {W}the {C}PDU Header{W}...")
        header_byte = PduGenerator.__generate_first_header_byte(self, pdu_type)

        data_length_bytes = PduGenerator.__to_bytes(self, pdu_data_length, 2) # PDU data length
        Vivify.vivify("{+} {G}Generated {W}the {C}Data Length Bytes {W}as: " + "{G}" + PduGenerator.__pretty_hex(self, data_length_bytes))

        entity_and_tsn_length_byte = bitarray()
        PduGenerator.__to_bits(self, 0, 1, entity_and_tsn_length_byte) # Reserved
        PduGenerator.__to_bits(self, PduGenerator.__get_int_byte_size(self, self.source_entity_id) - 1, 3, entity_and_tsn_length_byte) # Length of Entity IDs
        PduGenerator.__to_bits(self, 0, 1, entity_and_tsn_length_byte) # Reserved
        PduGenerator.__to_bits(self, PduGenerator.__get_int_byte_size(self, self.transaction_sequence_number) - 1, 3, entity_and_tsn_length_byte) # Length of Transaction Sequence Number
        Vivify.vivify("{+} {G}Generated {W}the {C}Entity ID & TSN Length Byte {W}as: " + "{G}" + PduGenerator.__pretty_hex(self, entity_and_tsn_length_byte))

        source_entity_bytes = PduGenerator.__to_bytes(self, self.source_entity_id, PduGenerator.__get_int_byte_size(self, self.source_entity_id)) # Source Entity ID
        Vivify.vivify("{+} {G}Generated {W}the {C}Source Entity ID Bytes {W}as: " + "{G}" + PduGenerator.__pretty_hex(self, source_entity_bytes))

        transaction_sequence_number_bytes = PduGenerator.__to_bytes(self, self.transaction_sequence_number, PduGenerator.__get_int_byte_size(self, self.transaction_sequence_number)) # Transaction Sequence Number
        Vivify.vivify("{+} {G}Generated {W}the {C}Transaction Sequence Number Bytes {W}as: " + "{G}" + PduGenerator.__pretty_hex(self, transaction_sequence_number_bytes))

        destination_entity_bytes = PduGenerator.__to_bytes(self, self.destination_entity_id, PduGenerator.__get_int_byte_size(self, self.destination_entity_id)) # Destination Entity ID
        Vivify.vivify("{+} {G}Generated {W}the {C}Destination Entity ID Bytes {W}as: " + "{G}" + PduGenerator.__pretty_hex(self, destination_entity_bytes))

        header = [
            header_byte,
            data_length_bytes,
            entity_and_tsn_length_byte,
            source_entity_bytes,
            transaction_sequence_number_bytes,
            destination_entity_bytes
        ]
        return header


    def __generate_first_header_byte(self, pdu_type: int) -> bitarray:
        """
        Generates the initial byte of a PDU header.
        """
        header_byte = bitarray()
        PduGenerator.__to_bits(self, 0, 3, header_byte) # CFDP Version
        PduGenerator.__to_bits(self, pdu_type, 1, header_byte) # PDU Type
        PduGenerator.__to_bits(self, 0, 1, header_byte) # Direction
        PduGenerator.__to_bits(self, 1, 1, header_byte) # Transmission Mode
        PduGenerator.__to_bits(self, 0, 1, header_byte) # CRC Flag
        PduGenerator.__to_bits(self, 0, 1, header_byte) # Reserved
        Vivify.vivify("{+} {G}Generated {W}the {C}first header byte {W}as: {G}" + PduGenerator.__pretty_hex(self, header_byte))
        return header_byte


    def __generate_pdu_metadata(self, file_directive_code: int) -> tuple[int, list[Union[bitarray, bytearray, bytes]]]:
        """
        Generates the bytes inside the data portion of the Metadata PDU.
        """
        Vivify.vivify("{*} {M}Generating {W}the {C}Metadata PDU{W}: {G}metadata.pdu")

        file_diretive_byte = PduGenerator.__to_bytes(self, file_directive_code, 1) # File Directive Code
        Vivify.vivify("{+} {G}Generated {W}the {C}File Directive Byte {W}as: {G}" + PduGenerator.__pretty_hex(self, file_diretive_byte))

        segmentation_control_byte = bitarray()
        PduGenerator.__to_bits(self, 1, 1, segmentation_control_byte) # Segmentation Control 
        PduGenerator.__to_bits(self, 0, 7, segmentation_control_byte) # Reserved
        Vivify.vivify("{+} {G}Generated {W}the {C}Segmentation Control Byte {W}as: {G}" + PduGenerator.__pretty_hex(self, segmentation_control_byte))

        file_size_bytes = PduGenerator.__to_bytes(self, os.path.getsize(self.source_file), 4) # File Size
        Vivify.vivify("{+} {G}Generated {W}the {C}File Size Bytes {W}as: {G}" + PduGenerator.__pretty_hex(self, file_size_bytes))

        source_filename_length_byte = PduGenerator.__to_bytes(self, len(os.path.basename(self.source_file)), PduGenerator.__get_int_byte_size(self, len(os.path.basename(self.source_file)))) # Length of Source File Name
        Vivify.vivify("{+} {G}Generated {W}the {C}Source Filename Length Byte {W}as: {G}" + PduGenerator.__pretty_hex(self, source_filename_length_byte))

        source_filename_bytes = os.path.basename(self.source_file).encode("ascii") # Encoded Source File Name
        Vivify.vivify("{+} {G}Generated {W}the {C}Source Filename Bytes {W}as: {G}" + PduGenerator.__pretty_hex(self, source_filename_bytes))

        destination_filename_length_byte = PduGenerator.__to_bytes(self, len(self.destination_file_name), PduGenerator.__get_int_byte_size(self, len(self.destination_file_name))) # Length of Destination File Name
        Vivify.vivify("{+} {G}Generated {W}the {C}Destination Filename Length Byte {W}as: {G}" + PduGenerator.__pretty_hex(self, destination_filename_length_byte))

        destination_filename_bytes = self.destination_file_name.encode("ascii") # Encoded Destination File Name
        Vivify.vivify("{+} {G}Generated {W}the {C}Destination Filename Bytes {W}as: {G}" + PduGenerator.__pretty_hex(self, destination_filename_bytes))

        metadata_byte_length = 8 + len(os.path.basename(self.source_file)) + len(self.destination_file_name) # Metadata PDU data length
        metadata = [
            file_diretive_byte,
            segmentation_control_byte,
            file_size_bytes,
            source_filename_length_byte,
            source_filename_bytes,
            destination_filename_length_byte,
            destination_filename_bytes
        ]
        return metadata_byte_length, metadata


    def __generate_metadata_pdu_file(self) -> None:
        """
        Generates the Metadata PDU.
        """
        metadata_byte_length, metadata = PduGenerator.__generate_pdu_metadata(self, 7)
        metadata_header = PduGenerator.__generate_pdu_header(self, 0, metadata_byte_length)
        with open("metadata.pdu", "wb") as pdu:
            for h in metadata_header:
                PduGenerator.__output(self, h, pdu)
            for m in metadata:
                PduGenerator.__output(self, m, pdu)


    def __generate_file_data_pdus(self) -> None:
        """
        Generates the File Data PDU(s) that contain the contents of the source file.
        """
        file_size = os.path.getsize(self.source_file)
        num_pdus = int(math.ceil(float(file_size) / float(self.pdu_file_data_chunk_size - 4)))

        with open(self.source_file, "rb") as source:
            data = source.read()

        for i in range(num_pdus):
            fname = "filedata_" + str(i) + ".pdu"
            Vivify.vivify("{*} {M}Generating {W}the {C}File Data PDU{W}: {G}" + fname)
            with open(fname, "wb") as pdu:
                offset = i * (self.pdu_file_data_chunk_size - 4)
                offset_bytes = PduGenerator.__to_bytes(self, offset, 4)
                Vivify.vivify("{+} {G}Generated {W}the {C}offset bytes {W}for {C}filedata_" + str(i) + ".pdu {W}as: {G}" + PduGenerator.__pretty_hex(self, offset_bytes))

                if offset + (self.pdu_file_data_chunk_size - 4) <= len(data):
                    data_bytes = data[offset:offset + (self.pdu_file_data_chunk_size - 4)]
                else:
                    data_bytes = data[offset:]
                Vivify.vivify("{+} {G}Generated {W}the {C}file data bytes {W}for {C}filedata_" + str(i) + ".pdu {W}as: {G}" + PduGenerator.__pretty_hex(self, data_bytes))

                header = PduGenerator.__generate_pdu_header(self, 1, 4 + len(data_bytes))
                for h in header:
                    PduGenerator.__output(self, h, pdu)

                pdu.write(offset_bytes)
                pdu.write(data_bytes)


    def __generate_eof_pdu(self) -> None:
        """
        Generates the End of File (EOF) PDU.
        """
        Vivify.vivify("{*} {M}Generating {W}the {C}End of File PDU{W}: {G}eof.pdu")

        checksum = PduGenerator.__calculate_file_checksum(self) # Source File Checksum
        Vivify.vivify("{+} {G}Generated {W}the {C}File Checksum {W}as: {G}" + str(checksum))

        file_directive_code = PduGenerator.__to_bytes(self, 4, 1)
        Vivify.vivify("{+} {G}Generated {W}the {C}File Directive Byte {W}as: {G}" + PduGenerator.__pretty_hex(self, file_directive_code))

        condition_code_and_spare_byte = PduGenerator.__to_bytes(self, 0, 1)
        Vivify.vivify("{+} {G}Generated {W}the {C}Condition Code Byte {W}as: {G}" + PduGenerator.__pretty_hex(self, condition_code_and_spare_byte))

        with open("eof.pdu", "wb") as pdu:
            header = PduGenerator.__generate_pdu_header(self, 0, 10)
            for h in header:
                PduGenerator.__output(self, h, pdu)

            pdu.write(file_directive_code)
            pdu.write(condition_code_and_spare_byte)

            for c in checksum.split():
                if len(c) % 2 == 0:
                    pdu.write(bytes.fromhex(c))
                else:
                    pdu.write(bytes.fromhex('0' + c))

            file_size_bytes = PduGenerator.__to_bytes(self, os.path.getsize(self.source_file), 4)
            pdu.write(file_size_bytes)


    def __calculate_file_checksum(self) -> str:
        """
        Calculates the checksum of the source file using the modular checksum algorithm.
        """
        with open(self.source_file, "rb") as source:
            data = source.read()

            checksum = [0, 0, 0, 0]
            for i in range(int(math.ceil(len(data) / 4.0))):
                if i != int(math.ceil(len(data) / 4.0)) - 1:
                    checksum[0] += data[i * 4]
                    checksum[1] += data[i * 4 + 1]
                    checksum[2] += data[i * 4 + 2]
                    checksum[3] += data[i * 4 + 3]
                else:
                    t1 = [0, 0, 0, 0]
                    t2 = data[i * 4:]
                    for j in range(len(t2)):
                        t1[j] += t2[j]

                    checksum[0] += t1[0]
                    checksum[1] += t1[1]
                    checksum[2] += t1[2]
                    checksum[3] += t1[3]

                # Perform Carry Over
                if checksum[0] > 255:
                    checksum[1] += checksum[0] - 255
                    checksum[0] = 255
                if checksum[1] > 255:
                    checksum[2] += checksum[1] - 255
                    checksum[1] = 255
                if checksum[2] > 255:
                    checksum[3] += checksum[2] - 255
                    checksum[2] = 255
                if checksum[3] > 255:
                    checksum[3] = 255

            return " ".join([hex(x)[2:] for x in checksum]).upper()


    def generate_pdus(self) -> None:
        """
        Generates the Metadata, File Data, and End Of File PDUs.
        """
        PduGenerator.__generate_metadata_pdu_file(self)
        PduGenerator.__generate_file_data_pdus(self)
        PduGenerator.__generate_eof_pdu(self)


if __name__ == "__main__":
    pdu_generator = PduGenerator(sys.argv[1:])
    pdu_generator.generate_pdus()
