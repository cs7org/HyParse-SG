"""
Factory responsible for selecting and creating
dataset-specific loaders.
"""

from dataset.swat_loader import SWaTLoader
from dataset.dnp3_loader import DNP3Loader
from dataset.sg_security_loader import SGSecurityLoader

class DatasetFactory:

    @staticmethod
    def create(dataset_type, file_path, limit=None):
        """
        Create dataset loader.

        Parameters
        ----------
        dataset_type : str
            Dataset identifier.

        file_path : str
            Path to dataset file.

        Returns
        -------
        Dataset loader instance
        """

        dataset_type = dataset_type.lower()

        # SWAT DATASET

        if dataset_type == "swat":

            return SWaTLoader(file_path, limit=limit)

        # SG SECURITY DATASET

        elif dataset_type == "sg_security":

            return SGSecurityLoader(file_path, limit=limit)

        # DNP3 DATASET

        elif dataset_type == "dnp3":

            return DNP3Loader(file_path, limit=limit)

        # UNSUPPORTED DATASET

        else:

            raise ValueError(
                f"Unsupported dataset type: {dataset_type}"
            )
