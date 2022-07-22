"""
taken from https://github.com/swilshin/toroidalsom/ and converted to Python 3


File toroidalsom.py
OVERVIEW
========
  An implementation of the Kohonen or self-organising map (SOM) in a space with
  the topology of an $N$-torus.
MAIN CLASSES
============

  L{ToroidalSOM} - This class implements the map, users should refer to the
  documentation of this class to get started.
TYPICAL USAGE
=============
  A usage example is included in the file toroidalsomexample.py
REFERENCES
==========
  Kohonen, Teuvo. "Self-organized formation of topologically correct feature
  maps." Biological cybernetics 43.1 (1982): 59-69.
LICENSE
=======

  This file is part of Simon Wilshin's toroidalsom module.
  Simon Wilshin's toroidalsom module is free software: you can redistribute
  it and/or modify it under the terms of the GNU General Public License as
  published by the Free Software Foundation, either version 3 of the License,
  or (at your option) any later version.
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
ACKNOWLEDGEMENTS
================
  Thanks are owed to the Royal Veterinary College where this software was
  developed and who supported its release under the GPL.
REQUIREMENTS
============
  Requires numpy. Example requires pylab.
@author: Simon Wilshin
@contact: swilshin@rvc.ac.uk
@date: Jul 2018
"""


from tqdm import tqdm
from copy import deepcopy
from numpy.random import randint
from numpy import random, ones, exp, zeros, arange, array, eye, pi, dot, nan, sum

'''
Useful functions for training the SOM
'''


def makeTrainFactor(step, Ntrain, tfac):
    """
    The scale of the squared exponential for the weights needs to decay in a
    suitable way so that early in the optimisation the scale is long, and
    later in the optimisation it is short. We achieve this by means of an
    exponential decay, with tfac determining how many cycles through the data we
    need to have had to achieve substantial decay in the width of the map
    we are considering.
    If tfac is 20 then after around 20 iterations through the data then the map
    will be updated on a scale sqrt(1/e) times the original scale.

    @param step: step number
    @type step: int
    @param Ntrain: number of training examples
    @type Ntrain: int
    @param tfac: number of iterations over which significant decay occurs
    @type tfac: int
    @return: scale factor
    @rtype: float

    """
    return exp(-float(step) / (Ntrain * tfac))


def guassianWeightScale(N, i, step, Ntrain, tfac, minscale=1e-9):
    """
    Calculates the weight to be assigned to the units in an update step
    based on how close they are to the best matching unit (BMU), and the
    number of steps that has already occurred.
    The idea is to start out optimising globally by pulling all units with
    at least some weight, then back off and make the updates more and more
    local for the map. Eventually only a small neighbourhood around the BMU is
    updated. How fast we go from one state of affairs to the other is determined
    by tfac.

    @param N: number of elements in the map
    @type N: int
    @param i: iteration number
    @type i: int
    @param Ntrain: number of training examples
    @type Ntrain: int
    @param tfac: number of iterations over which significant decay occurs
    @type tfac: int
    @param minscale: training factor only BMU weight adjusted
    @type minscale: float
    @return: weights
    @rtype: array of floats
    """
    # Ensure step needs to be ~ Ntrain*tfac for decay to have importance
    trainFac = makeTrainFactor(step, Ntrain, tfac)
    # minscale determines the point where we start treating the best matching
    # unit (BMU) as the only unit that counts. It should be much less than
    # 1./N, and is used to ensure that floating point precision problems
    # don't result in a trainFac of 0. giving nans for the weight of the
    # BMU. Instead we just approximate this case as assigning weight to only the
    # BMU.
    if trainFac < minscale:
        r = zeros((N,), dtype=float)
        r[i] = 1.0
        return (r)
    else:
        return exp(-(((arange(N) - i) ** 2)) / (2 * N * N * trainFac))


def torusDistanceFunction(x0, x1, g):
    """
    Computes the Euclidean distance between all of the vectors in
    x0 (NxM) and all of the vectors in x1 (kxM), using metric g (MxM),
    modulo the topology of the torus (co-ordinates range from 0 to 2*pi). The
    distance here being defined as the length of the shortest path between the
    two points on the torus.

    Returns the distance matrix (kxN).
    @param x0: first array of vectors
    @type x0: array of floats
    @param x1: second array of vectors
    @type x1: array of floats
    @param g: metric
    @type g: array of floats
    @return: distances
    @rtype: array of floats
    """
    dists = (
                    (
                            x1.repeat(x0.shape[0]).reshape(x1.shape[0], x1.shape[1], x0.shape[0])
                            -
                            x0.transpose() + pi
                    ) % (2.0 * pi)
            ) - pi
    return sum(dists * ((dot(g, dists))).transpose(1, 0, 2), 1)


class ToroidalSOM(object):
    """
    Implements a self-organising map on a torus (although with a suitable choice
    of distfun a more conventional SOM could be implemented). The constructor
    does not initialize the elements of the map, to initialise with
    random weights the member function random_initialisation should be called.

    @ivar Nmap: Number of elements of the map
    @type Nmap: int
    @ivar D: Dimension of the space we are fitting the map to
    @type D: int
    @ivar xmap: The weights for the SOM units
    @type xmap: array of floats
    @ivar xmap0: Initial weights for the SOM units
    @type xmap0: array of floats
    @ivar distfun: The weights for the SOM units
    @type distfun: function with call signature f(x0,x1) with x0 and x1 kxM
    arrays and returning a kxk array of distances.
    @ivar weightfun: See L{guassianWeightScale} for an example
    @type weightfun: function with call signature f(N,i,step,Ntrain,tfac)
    """

    def __init__(
            self,
            Nmap, D,
            distfun=torusDistanceFunction, weightfun=guassianWeightScale
    ):
        """
        Instantiate the self organising map.

        @param Nmap: number of elements in the map
        @type Nmap: int
        @param D: dimension of feature space
        @type D: int
        @param distfun: The weights for the SOM units
        @type distfun: function with call signature f(x0,x1) with x0 and x1 kxM
        arrays and returning a kxk array of distances.
        @param weightfun: See L{guassianWeightScale} for an example
        @type weightfun: function with call signature f(N,i,step,Ntrain,tfac)
        """
        self.Nmap = Nmap
        self.D = D
        self.xmap = nan * ones((D, Nmap))  # Allocate the SOM weights, nans to start
        self.xmap0 = nan * ones((D, Nmap))  # Allocate the initial SOM weights
        self.distfun = distfun  # Function used to compute distances
        self.weightfun = weightfun  # Function used to compute weights

    def random_initialisation(self):
        """
        Initialise the weights of the SOM to random numbers between 0 and 2*pi.
        """
        self.xmap0 = (2 * pi) * random.rand(
            self.D * self.Nmap
        ).reshape((self.D, self.Nmap))
        self.xmap = deepcopy(self.xmap0)

    def iteration(self, x, i0, i, tfac, alpha0, Nit):
        """
        Perform a single iteration to train the map. In an iteration an example
        from the training data set is taken and the closest element of the map is
        found. Weights of the elements of the self-organising map are then
        calculated and the elements are then pulled towards the training example
        in proportion to their weight.

        The weight function offset is used to make the initial adjustments of the
        weights a little less global, set this to a positive integer around 10%
        of the total number of iterations to spend a little less time adjusting
        map as a whole.

        If the map is converging slowly consider increasing alpha0, if it is
        failing to converge consider increasing it.

        @param x: training examples
        @type x: array of floats
        @param i0: weight function offset
        @type i0: int
        @param i: current iteration
        @type i: int
        @param tfac: number of iterations over which significant decay occurs
        @type tfac: int
        @param alpha0: base learning rate
        @type alpha0: float
        """
        Ntrain = x.shape[0]
        # Grab training example
        tx = x[randint(0, Ntrain)]

        # Calculate distances
        Dmap = self.distfun(array([tx]), self.xmap.T, eye(self.D))[:, 0]
        iBMU = Dmap.argmin()

        # Calculate weight function
        tl = self.weightfun(self.Nmap, iBMU, i0 + i, Ntrain, tfac)
        alpha = alpha0 * exp(-i / float(Nit))

        # Update map
        self.xmap = self.xmap + tl * alpha * ((tx - self.xmap.T + pi) % (2 * pi) - pi).T

    def fit(self, x, tfac, tscale, alpha0):
        """
        Perform the fitting loop for tfac*tscale*x.shape[0] repetitions.

        @param x: training examples
        @type x: array of floats
        @param tfac: number of iterations over which significant decay occurs
        @type tfac: int
        @param tscale: use this to adjust the total number of iterations
        @type tscale: float
        @param alpha0: base learning rate
        @type alpha0: float
        """
        Ntrain = x.shape[0]
        i0 = 1 * Ntrain
        Nit = tfac * tscale * Ntrain
        bar = tqdm(range(Nit), 'training'.rjust(27), unit=" epochs")
        for i in bar:
            if i % Ntrain == 0:
                '''
                Here we print some diagnostic data, note that the 'iteration' here 
                refers to each time we consider Ntrain test examples from the training 
                data, not each time we consider a single training example.
                '''
                bar.set_description(f"Iteration: {i / Ntrain} of {Nit / Ntrain} and training factor: {makeTrainFactor(i0 + i, Ntrain, tfac)}")
            self.iteration(x, i0, i, tfac, alpha0, Nit)
        self.xmap = self.xmap % (2. * pi)
